import Lean

open Lean Meta Elab

namespace Naome

inductive NamePart where
  | text (value : String)
  | number (value : Nat)
  deriving ToJson, FromJson

structure WireName where
  parts : List NamePart
  deriving ToJson, FromJson

def WireName.encode (name : Name) : WireName := ⟨go name []⟩
where
  go : Name → List NamePart → List NamePart
    | .anonymous, parts => parts
    | .str parent value, parts => go parent (.text value :: parts)
    | .num parent value, parts => go parent (.number value :: parts)

def WireName.decode (name : WireName) : Name :=
  name.parts.foldl (init := .anonymous) fun parent part =>
    match part with
    | .text value => .str parent value
    | .number value => .num parent value

inductive WireLevel where
  | zero
  | succ (level : WireLevel)
  | max (left right : WireLevel)
  | imax (left right : WireLevel)
  | parameter (name : WireName)
  deriving ToJson, FromJson

def WireLevel.decode : Nat → WireLevel → Except String Level
  | 0, _ => throw "universe depth exceeded"
  | _ + 1, .zero => pure .zero
  | fuel + 1, .succ level => return .succ (← decode fuel level)
  | fuel + 1, .max left right => return .max (← decode fuel left) (← decode fuel right)
  | fuel + 1, .imax left right => return .imax (← decode fuel left) (← decode fuel right)
  | _ + 1, .parameter name => pure (.param name.decode)

def WireLevel.encode : Level → Except String WireLevel
  | .zero => pure .zero
  | .succ level => return .succ (← encode level)
  | .max left right => return .max (← encode left) (← encode right)
  | .imax left right => return .imax (← encode left) (← encode right)
  | .param name => pure (.parameter (WireName.encode name))
  | .mvar _ => throw "unresolved universe"

inductive WireExpr where
  | variable (index : Nat)
  | sort (level : WireLevel)
  | constant (name : WireName) (levels : List WireLevel)
  | apply (function argument : WireExpr)
  | lambda (name : WireName) (type body : WireExpr) (binder : Nat)
  | forallE (name : WireName) (type body : WireExpr) (binder : Nat)
  | letE (name : WireName) (type value body : WireExpr) (nondependent : Bool)
  | natLit (value : Nat)
  | stringLit (value : String)
  | projection (typeName : WireName) (index : Nat) (subject : WireExpr)
  deriving ToJson, FromJson

def encodeBinder : BinderInfo → Nat
  | .default => 0
  | .implicit => 1
  | .strictImplicit => 2
  | .instImplicit => 3

def decodeBinder : Nat → Except String BinderInfo
  | 0 => pure .default
  | 1 => pure .implicit
  | 2 => pure .strictImplicit
  | 3 => pure .instImplicit
  | _ => throw "invalid binder annotation"

partial def WireExpr.encode : Expr → Except String WireExpr
  | .bvar index => pure (.variable index)
  | .sort level => return .sort (← WireLevel.encode level)
  | .const name levels => return .constant (WireName.encode name) (← levels.mapM WireLevel.encode)
  | .app fn arg => return .apply (← encode fn) (← encode arg)
  | .lam name type body binder =>
    return .lambda (WireName.encode name) (← encode type) (← encode body) (encodeBinder binder)
  | .forallE name type body binder =>
    return .forallE (WireName.encode name) (← encode type) (← encode body) (encodeBinder binder)
  | .letE name type value body nondependent =>
    return .letE (WireName.encode name) (← encode type) (← encode value) (← encode body) nondependent
  | .lit (.natVal value) => pure (.natLit value)
  | .lit (.strVal value) => pure (.stringLit value)
  | .mdata _ expr => encode expr
  | .proj typeName index subject => return .projection (WireName.encode typeName) index (← encode subject)
  | _ => throw "expression contains a free variable or metavariable"

partial def WireExpr.decode (fuel scope : Nat) (expr : WireExpr) : Except String Expr := do
  if fuel == 0 then throw "expression depth exceeded"
  let descend := decode (fuel - 1) scope
  let underBinder := decode (fuel - 1) (scope + 1)
  match expr with
  | .variable index =>
    if index < scope then pure (.bvar index) else throw "unbound de Bruijn index"
  | .sort level => return .sort (← level.decode fuel)
  | .constant name levels => return .const name.decode (← levels.mapM (WireLevel.decode fuel))
  | .apply fn arg => return .app (← descend fn) (← descend arg)
  | .lambda name type body binder =>
    return .lam name.decode (← descend type) (← underBinder body) (← decodeBinder binder)
  | .forallE name type body binder =>
    return .forallE name.decode (← descend type) (← underBinder body) (← decodeBinder binder)
  | .letE name type value body nondependent =>
    return .letE name.decode (← descend type) (← descend value) (← underBinder body) nondependent
  | .natLit value => pure (.lit (.natVal value))
  | .stringLit value => pure (.lit (.strVal value))
  | .projection typeName index subject => return .proj typeName.decode index (← descend subject)


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
  kernel : Json
  names : Array (String × String)
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
  kernel : Json := .null
  dependencies : Array String := #[]
  question : Json := .null
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

def checkedAxioms (name : Name) : CoreM (Array String) := do
  let axioms ← collectAxioms name
  for axiomName in axioms do
    unless trustedAxioms.contains axiomName do
      throwError "unapproved axiom {axiomName}"
  return axioms.map Name.toString

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
  checkedAxioms name

def declarationSymbols (type : Expr) (value : Option Expr := none) : Array String :=
  symbols type ++ (value.map symbols).getD #[]

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

structure KernelTerms where
  isProof : Bool
  levelParameters : List WireName
  type : WireExpr
  value : WireExpr
  deriving FromJson, ToJson

def isArchiveName (name : Name) : Bool :=
  (`NaomeArchive).isPrefixOf name

def archiveConstants (type value : Expr) : Array Name :=
  (type.getUsedConstants ++ value.getUsedConstants).toList
    |>.filter isArchiveName |>.mergeSort Name.lt |>.eraseDups |>.toArray

partial def eraseBinderNames : Expr → Expr
  | .forallE _ type body binder => .forallE .anonymous (eraseBinderNames type) (eraseBinderNames body) binder
  | .lam _ type body binder => .lam .anonymous (eraseBinderNames type) (eraseBinderNames body) binder
  | .letE _ type value body _ =>
    .letE .anonymous (eraseBinderNames type) (eraseBinderNames value) (eraseBinderNames body) false
  | .app fn arg => .app (eraseBinderNames fn) (eraseBinderNames arg)
  | .mdata _ body => eraseBinderNames body
  | .proj name index body => .proj name index (eraseBinderNames body)
  | expr => expr

def questionNames (type : Expr) : Array Name :=
  type.getUsedConstants.toList.filter isArchiveName |>.mergeSort Name.lt |>.toArray

def questionType (type : Expr) : Expr :=
  let type := eraseBinderNames type
  let names := (collectLevelParams {} type).params
  let levels := names.mapIdx fun index _ => Level.param (.num .anonymous index)
  type.instantiateLevelParamsArray names levels

def describeQuestion (type : Expr) : CoreM Json := do
  let expression ← ofExcept (WireExpr.encode (questionType type))
  return Json.mkObj [
    ("term", toJson expression),
    ("dependencies", toJson ((questionNames type).map Name.toString))]

def checkQuestion (worker : Worker) (req : Request) : IO (Worker × Reply) := do
  let type ← if req.kernel == .null then do
    let stx ← parseTerm worker.env req.target
    let (type, core, _) ← ((elaborate stx none).run' : MetaM Expr).toIO coreContext { env := worker.env }
    if core.messages.hasErrors then
      let messages ← core.messages.toList.mapM fun message => message.data.toString
      throw (IO.userError (String.intercalate "\n" messages))
    pure (questionType type)
  else do
    let encoded : WireExpr ← IO.ofExcept (fromJson? req.kernel)
    let type ← IO.ofExcept (encoded.decode 256 0)
    let normalized ← IO.ofExcept (WireExpr.encode (questionType type))
    unless toJson normalized == req.kernel do
      throw (IO.userError "noncanonical question term")
    pure type
  let used := questionNames type
  let declared := (req.dependencies.map String.toName).toList.mergeSort Name.lt
  unless declared == used.toList do
    throw (IO.userError "archive dependencies differ from question type")
  let name := `NaomeQuestion.verify
  let declaration := Declaration.thmDecl {
    name
    levelParams := (collectLevelParams {} type).params.toList
    type := .forallE .anonymous type (type.liftLooseBVars 0 1) .default
    value := .lam .anonymous type (.bvar 0) .default
  }
  let check : CoreM Reply := do
    match worker.env.addDeclCore 200000 512 declaration none (doCheck := true) with
    | .error failure => throwKernelException failure
    | .ok checked => setEnv checked
    unless ← MetaM.run' (isProp type) do
      throwError "question type must be a proposition"
    let _ ← checkedAxioms name
    return { question := ← describeQuestion type }
  let (reply, _) ← check.toIO coreContext { env := worker.env }
  return (worker, reply)

def exportKernel (worker : Worker) (req : Request) : IO (Worker × Reply) := do
  let name := req.declaration.toName
  let some info := worker.env.find? name | throw (IO.userError "missing checked declaration")
  let some value := info.value? (allowOpaque := true) | throw (IO.userError "missing declaration body")
  let aliases := req.names.map fun (old, replacement) => (old.toName, replacement.toName)
  let used := archiveConstants info.type value
  unless used.all (fun name => aliases.any (·.1 == name)) do
    throw (IO.userError "missing portable name for a used declaration")
  let rewrite := Expr.replace fun expr => do
    let .const name universes := expr | none
    let (_, replacement) ← aliases.find? (·.1 == name)
    return .const replacement universes
  let isProof := match info with | .thmInfo _ => true | _ => false
  let type := rewrite info.type
  let value := rewrite value
  let terms : KernelTerms ← IO.ofExcept do
    return {
      isProof
      levelParameters := info.levelParams.map WireName.encode
      type := ← WireExpr.encode type
      value := ← WireExpr.encode value }
  return (worker, { kernel := toJson terms, dependencies := (archiveConstants type value).map Name.toString })

def importKernel (worker : Worker) (req : Request) : IO (Worker × Reply) := do
  let terms : KernelTerms ← IO.ofExcept (fromJson? req.kernel)
  unless toJson terms == req.kernel do
    throw (IO.userError "noncanonical kernel term")
  let name := req.declaration.toName
  unless isArchiveName name do
    throw (IO.userError "invalid archive name")
  let type ← IO.ofExcept (terms.type.decode 256 0)
  let value ← IO.ofExcept (terms.value.decode 256 0)
  let declared := (req.dependencies.map String.toName).toList.mergeSort Name.lt
  unless declared == (archiveConstants type value).toList do
    throw (IO.userError "archive dependencies differ from kernel terms")
  let levelParams := terms.levelParameters.map WireName.decode
  let declaration := if terms.isProof then
    Declaration.thmDecl { name, levelParams, type, value }
  else
    Declaration.defnDecl { name, levelParams, type, value, hints := .abbrev, safety := .safe }
  let check : CoreM Reply := do
    match worker.env.addDeclCore 200000 512 declaration none (doCheck := true) with
    | .error failure => throwKernelException failure
    | .ok checked => setEnv checked
    let axioms ← checkedAxioms name
    let target ← MetaM.run' (return (← ppExpr type).pretty)
    let symbols := declarationSymbols type (if terms.isProof then none else some value)
    let question ← if terms.isProof then describeQuestion type else pure .null
    return { axioms, symbols, view := { target }, question }
  let (reply, state) ← check.toIO coreContext { env := worker.env }
  return ({ env := state.env }, reply)

def dispatch (worker : Worker) (req : Request) : IO (Worker × Reply) :=
  match req.op with
  | "start" => start worker req
  | "step" => step worker req
  | "finish" => finish worker req
  | "define" => define worker req
  | "exportKernel" => exportKernel worker req
  | "importKernel" => importKernel worker req
  | "question" => checkQuestion worker req
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
