import Lean

open Lean Meta Elab

namespace Naome

structure Request where
  op : String
  target : String
  value : String
  state : Nat
  action : Nat
  source : String
  name : String
  index : Nat
  declaration : String
  dependencies : Array String
  references : Array String
  describeActions : Bool
  deriving FromJson

structure Signature where
  conclusion : String := ""
  premises : Array String := #[]
  conclusionSymbols : Array String := #[]
  premiseSymbols : Array (Array String) := #[]
  deriving ToJson, Inhabited

structure View where
  state : Nat := 0
  pending : Nat := 0
  target : String := ""
  head : String := ""
  locals : Array String := #[]
  targetSymbols : Array String := #[]
  localSignatures : Array Signature := #[]
  referenceSignatures : Array Signature := #[]
  deriving ToJson, Inhabited

structure Reply where
  accepted : Bool := true
  error : String := ""
  view : View := {}
  axioms : Array String := #[]
  symbols : Array String := #[]
  deriving ToJson, Inhabited

structure Frame where
  root : Expr
  goals : List MVarId
  metaState : Meta.State
  core : Core.State

structure Worker where
  env : Environment
  frames : Array Frame := #[]

def coreContext : Core.Context :=
  { fileName := "<naome>", fileMap := default,
    options := ({} : Options).setBool `pp.fullNames true
      |>.setBool `autoImplicit false
      |>.setBool `Elab.async false
      |>.setBool `debug.skipKernelTC false
      |>.set `maxHeartbeats (200000 : Nat) }

def parseTerm (env : Environment) (source : String) : IO Syntax :=
  match Parser.runParserCategory env `term source with
  | .ok stx => pure stx
  | .error message => throw (IO.userError message)

def elaborate (stx : Syntax) (expected : Option Expr) : TermElabM Expr := do
  let value ← match expected with
    | some type => Term.elabTermEnsuringType stx type
    | none => Term.elabType stx
  Term.synthesizeSyntheticMVarsNoPostponing
  let value ← Term.levelMVarToParam (← instantiateMVars value)
  if value.hasMVar || value.hasFVar then
    throwError "declaration must be closed"
  pure value

def localExprs : MetaM (Array Expr) := do
  let mut result := #[]
  for declaration in (← getLCtx) do
    if !declaration.isImplementationDetail then
      result := result.push (mkFVar declaration.fvarId)
  pure result

def expressionHead (expr : Expr) : String :=
  if expr.isForall then "forall"
  else expr.getAppFn.constName?.map Name.toString |>.getD ""

def symbols (expr : Expr) : Array String :=
  expr.getUsedConstants.map Name.toString

def signature (type : Expr) (partialSignature : Signature := {}) : Signature :=
  match type with
  | .forallE _ domain body info =>
    if info.isExplicit then
      signature body { partialSignature with
        premises := partialSignature.premises.push (expressionHead domain)
        premiseSymbols := partialSignature.premiseSymbols.push (symbols domain) }
    else signature body partialSignature
  | _ => { partialSignature with conclusion := expressionHead type, conclusionSymbols := symbols type }

def describe (state : Nat) (goals : List MVarId) (describeActions : Bool) : MetaM View := do
  let some goal := goals.head? | return { state }
  goal.withContext do
    let target ← instantiateMVars (← goal.getType)
    let head := if target.isForall then "forall" else
      target.getAppFn.constName?.map Name.toString |>.getD "other"
    let types ← (← localExprs).mapM fun expr => inferType expr >>= instantiateMVars
    let locals ← types.mapM fun type => return (← ppExpr type).pretty
    let localSignatures := if describeActions then types.map fun type => signature type else #[]
    let pretty := (← ppExpr target).pretty
    let targetSymbols := if describeActions then symbols target else #[]
    return { state, pending := goals.length, target := pretty, head, locals, localSignatures, targetSymbols }

def start (worker : Worker) (req : Request) : IO (Worker × Reply) := do
  let stx ← parseTerm worker.env req.target
  let action : MetaM (Expr × List MVarId × View) := do
    let type ← (elaborate stx none).run'
    unless ← isProp type do
      throwError "proof goal must be a proposition"
    let root ← mkFreshExprSyntheticOpaqueMVar type
    let goals := [root.mvarId!]
    let view ← describe 0 goals req.describeActions
    let env ← getEnv
    let referenceSignatures := req.references.map fun name =>
      match env.find? name.toName with
      | some info => signature info.type
      | none => default
    return (root, goals, { view with referenceSignatures })
  let ((root, goals, view), core, metaState) ← action.toIO coreContext { env := worker.env }
  return ({ worker with frames := #[{ root, goals, core := { core with env := worker.env }, metaState }] }, { view })

def argument (req : Request) : TermElabM Term := do
  match req.source with
  | "local" =>
    let locals ← localExprs
    match locals[req.index]? with
    | some expr => Term.exprToSyntax expr
    | none => throwError "local argument is out of scope"
  | "declaration" => pure ⟨mkCIdent req.name.toName⟩
  | _ => throwError "expected a local or declaration argument"

def runAction (goal : MVarId) (req : Request) : TermElabM (List MVarId) :=
  Tactic.run goal do
    let stx ← match req.action with
      | 0 => `(tactic| intro)
      | 1 => do
        let term ← argument req
        `(tactic| exact $term)
      | 2 => do
        let term ← argument req
        `(tactic| apply $term)
      | 3 => `(tactic| constructor)
      | 4 => `(tactic| rfl)
      | _ => throwError "unknown proof action"
    Tactic.evalTactic stx

def step (worker : Worker) (req : Request) : IO (Worker × Reply) := do
  let some frame := worker.frames[req.state]? | throw (IO.userError "unknown proof state")
  let current :: rest := frame.goals | throw (IO.userError "proof state is already complete")
  let next := worker.frames.size
  let action : MetaM (List MVarId × View) := current.withContext do
    let created ← (runAction current req).run'
    let goals ← (created ++ rest).filterM fun goal => return !(← goal.isAssigned)
    return (goals, ← describe next goals req.describeActions)
  let ((goals, view), core, metaState) ← action.toIO coreContext frame.core {} frame.metaState
  if core.messages.hasErrors then
    throw (IO.userError "Lean reported a tactic error")
  return ({ worker with frames := worker.frames.push { frame with goals, core, metaState } }, { view })

def trustedAxioms : Array Name := #[`propext, `Classical.choice, `Quot.sound]

def checkDeclaration (req : Request) (type value : Expr) (decl : Declaration) :
    CoreM (Array String) := do
  let allowed := req.dependencies
  let constants := type.getUsedConstants ++ value.getUsedConstants
  for constant in constants do
    let name := constant.toString
    if name.startsWith "NaomeArchive.e_" && !allowed.contains name then
      throwError "undeclared archive dependency {name}"
  let name := req.declaration.toName
  Lean.addDecl decl
  let axioms ← collectAxioms name
  for axiomName in axioms do
    unless trustedAxioms.contains axiomName do
      throwError "unapproved axiom {axiomName}"
  return axioms.map Name.toString

def declarationSymbols (type : Expr) (value : Option Expr := none) : Array String :=
  let sig := signature type
  sig.conclusionSymbols ++ sig.premiseSymbols.flatten ++
    (value.map symbols).getD #[]

def finish (worker : Worker) (req : Request) : IO (Worker × Reply) := do
  let some frame := worker.frames[req.state]? | throw (IO.userError "unknown proof state")
  unless frame.goals.isEmpty do
    throw (IO.userError "proof has unresolved goals")
  let action : MetaM Reply := do
    let type ← instantiateMVars (← inferType frame.root)
    let value ← instantiateMVars frame.root
    if type.hasMVar || value.hasMVar || type.hasFVar || value.hasFVar then
      throwError "proof term is not closed"
    let decl := Declaration.thmDecl {
      name := req.declaration.toName
      levelParams := ((collectLevelParams {} type).collect value).params.toList
      type := type
      value := value
    }
    let axioms ← checkDeclaration req type value decl
    return { axioms, symbols := declarationSymbols type }
  let (reply, core, _) ← action.toIO coreContext frame.core {} frame.metaState
  return ({ env := core.env }, reply)

def define (worker : Worker) (req : Request) : IO (Worker × Reply) := do
  let typeSyntax ← parseTerm worker.env req.target
  let valueSyntax ← parseTerm worker.env req.value
  let action : TermElabM Reply := do
    let type ← elaborate typeSyntax none
    let value ← elaborate valueSyntax (some type)
    let decl := Declaration.defnDecl {
      name := req.declaration.toName
      levelParams := ((collectLevelParams {} type).collect value).params.toList
      type := type
      value := value
      hints := .abbrev
      safety := .safe
    }
    setEnv worker.env
    let axioms ← checkDeclaration req type value decl
    return { axioms, symbols := declarationSymbols type (some value) }
  let (reply, core, _, _) ← action.toIO coreContext { env := worker.env } {} {} {} {}
  return ({ env := core.env }, reply)

def dispatch (worker : Worker) (req : Request) : IO (Worker × Reply) :=
  match req.op with
  | "start" => start worker req
  | "step" => step worker req
  | "finish" => finish worker req
  | "define" => define worker req
  | _ => throw (IO.userError "unknown bridge operation")

end Naome

unsafe def main : IO Unit := do
  initSearchPath (← findSysroot)
  enableInitializersExecution
  let env ← importModules #[
    { module := `Mathlib.SetTheory.ZFC.Basic },
    { module := `Mathlib.Data.List.Basic },
    { module := `Mathlib.Data.Option.Basic },
    { module := `Mathlib.Data.Set.Basic },
    { module := `Mathlib.Data.Nat.Basic }
  ] {} (loadExts := true)
  let input ← IO.getStdin
  let output ← IO.getStdout
  let mut worker : Naome.Worker := { env }
  output.putStrLn s!"naome-lean {Lean.versionString}"
  output.flush
  repeat
    let line ← input.getLine
    if line.isEmpty then break
    let reply : Naome.Reply ←
      match Json.parse line >>= fromJson? with
      | .error error => pure { accepted := false, error }
      | .ok req =>
        try
          let (next, reply) ← Naome.dispatch worker req
          worker := next
          pure reply
        catch error => pure { accepted := false, error := error.toString }
    output.putStrLn (toJson reply).compress
    output.flush
