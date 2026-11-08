//! Numeric identifiers for machine outcomes exported by the node.
//! Each domain owns a disjoint range. Exported values are assigned explicitly.
macro_rules! codes {
    ($( $visibility:vis enum $name:ident in $domain:literal { $($variant:ident = $id:literal),+ $(,)? } )+) => {
        #[repr(u16)]
        enum Domain {
            $($name = $domain),+
        }
        $(codes!(@domain $visibility enum $name { $($variant = $id),+ });)+

        /// Domain, outcome name and canonical code for offline tooling.
        #[cfg(feature = "developer-tools")]
        pub const OUTCOME_CODES: &[(&str, &str, u32)] = &[
            $($( (stringify!($name), stringify!($variant), $name::$variant as u32), )+)+
        ];
    };
    (@domain $visibility:vis enum $name:ident { $($variant:ident = $id:literal),+ }) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
        #[repr(u32)]
        #[serde(try_from = "u32", into = "u32")]
        $visibility enum $name {
            $($variant = ((Domain::$name as u32) << 16) | $id),+
        }

        impl From<$name> for u32 {
            fn from(value: $name) -> Self {
                value as u32
            }
        }

        impl TryFrom<u32> for $name {
            type Error = &'static str;

            fn try_from(value: u32) -> Result<Self, Self::Error> {
                match value {
                    $(value if value == Self::$variant as u32 => Ok(Self::$variant),)+
                    _ => Err("unknown outcome code"),
                }
            }
        }

        const _: () = {
            assert!(Domain::$name as u16 > 0);
            $(assert!($id > 0 && $id <= u16::MAX as u32);)+
        };
    };
}

codes! {
    pub(crate) enum PeerFailure in 1 {
        OwnerBusy = 1,
        Disabled = 2,
        Incompatible = 3,
        RateLimited = 4,
        ComputationPaused = 5,
        ProgramResourcesPaused = 6,
        InvalidRequest = 7,
        ResourceUnavailable = 8,
        RequestFailed = 9,
        UnexpectedRequest = 10,
        RequiredPayloadMissing = 11,
        UnexpectedResponse = 12,
    }

    pub(crate) enum EvidenceCode in 2 {
        Limit = 1,
        Framing = 2,
        Compression = 3,
        Definitions = 4,
    }

    pub enum DurabilityCode in 3 {
        CommitUnconfirmed = 1,
        RollbackUnconfirmed = 2,
        CatalogGeneration = 3,
        CatalogCommit = 4,
        ProgramCommit = 5,
        QuestionPublication = 6,
    }

    pub enum PauseReason in 4 {
        MemoryPressure = 1,
        DiskPressure = 2,
        SystemMemoryPressure = 3,
        ProcessTreeMemoryPressure = 4,
        HardwareObservationUnavailable = 5,
        PowerSaving = 6,
        ThermalPressure = 7,
        ExternalCpuPressure = 8,
        ResourceStateUnavailable = 9,
        NoComputationBudget = 10,
    }

    pub(crate) enum OfferStatus in 5 {
        Queued = 1,
        Duplicate = 2,
        QueuedDuplicate = 3,
        MetadataRefreshed = 4,
        Declined = 5,
        Unselected = 6,
        AwaitingDefinition = 7,
        CitedProgramPending = 8,
    }

    pub(crate) enum OperationCode in 6 {
        MemoryOverload = 1,
        DiskOverload = 2,
        ExecutionLimit = 3,
        StaleAuthority = 4,
        Deadline = 5,
        InvalidInput = 6,
        MissingQuestionDefinition = 7,
        ProofCheck = 8,
        DiagnosticInspection = 9,
        CertificateFormat = 10,
        InvalidStoredRecord = 11,
        CorruptStorage = 12,
        QuestionLimit = 13,
        ExecutionFailed = 14,
        ProgramCodec = 15,
        QuestionInput = 16,
        ProgramInput = 17,
        ProgramFormula = 18,
    }

    pub enum InputFault in 7 {
        DescriptionAddressMismatch = 1,
        ArtifactCompatibilityMismatch = 2,
        CheckedIdentityMismatch = 3,
    }

    pub enum InputLimit in 8 {
        CliJsonAllocationBudgetOverflow = 1,
        CliJsonAllocationLimit = 2,
        ArtifactByteLimit = 3,
        CheckedClosureOperationCapacity = 4,
        CheckpointHeaderCapacity = 5,
        CheckpointRecordCapacity = 6,
        CitedClosureDependencyCapacity = 7,
        CitedClosureOperationCapacity = 8,
        DependencyCountLimit = 9,
        EmptyCertificate = 10,
        InventoryPageLimit = 11,
        InventoryPageLimitMustBePositive = 12,
        ProgramClosureDependencyCapacity = 13,
        StagedCertificateByteCapacity = 14,
        StagedClosureByteOverflow = 15,
        StagedClosureDependencyCapacity = 16,
        StagedClosureObjectOverflow = 17,
        StagedClosureResourceCapacity = 18,
        StagedClosureStepOverflow = 19,
        StagedClosureStepWorkLimit = 20,
        TrainingDiagnosticPageLimit = 21,
        TrainingQuestionPageLimit = 22,
        TrainingSelectionPageLimit = 23,
        TrainingSuitePageLimit = 24,
    }

    pub(crate) enum WorkerFailure in 9 {
        ProviderRejected = 1,
        ProviderUncertain = 2,
        CleanupUnconfirmed = 3,
        Cancelled = 4,
        Deadline = 5,
        Execution = 6,
        Panic = 7,
        ReplayUnavailable = 8,
        NoReplayCandidate = 9,
        ReplayNotSelected = 10,
        ReplayAdmissionLimit = 11,
    }
    pub enum LearningGraphFailure in 10 {
        Capacity = 1,
        ActionArity = 2,
        BoundIndexWidth = 3,
        DanglingBoundVariable = 4,
        DecisionCapacity = 5,
        MissingExpert = 6,
        MissingPremise = 7,
    }

    pub(crate) enum WireFailure in 11 {
        FrameLimit = 1,
        FrameCapacity = 2,
        TrailingFrameBytes = 3,
        FrameMemory = 4,
        ControlRecord = 5,
        ArtifactKind = 6,
        ArtifactAddress = 7,
        ArtifactPayloadLimit = 8,
        ArtifactPayloadEncoding = 9,
        TruncatedArtifact = 10,
        InvalidArtifactFlag = 11,
        ArtifactCompression = 12,
        ProgramEncoding = 13,
        DialFailed = 14,
        TimedOut = 15,
        ConnectionClosed = 16,
        UnsupportedProtocols = 17,
        ResponseOmitted = 18,
        StreamIo = 19,
        NoAddress = 20,
        DialCondition = 21,
        Aborted = 22,
        IdentityMismatch = 23,
        SelfConnection = 24,
        AdmissionDenied = 25,
        TransportNegotiation = 26,
        OriginPeerLimit = 27,
        EndpointRequired = 28,
        HandshakeCapacity = 29,
        HandshakeRateLimit = 30,
        ReservedOutboundCapacity = 31,
        ConnectionCapacity = 32,
        ContactCapacity = 33,
        ResponsePeerMismatch = 34,
        DescriptionIdentityMismatch = 35,
        ResponseScopeMismatch = 36,
        UnsolicitedInventory = 37,
        InvalidInventory = 38,
        ContactRetirementCapacity = 39,
    }

    pub enum RuntimeFailure in 12 {
        Arguments = 1,
        Resources = 2,
        Directory = 3,
        ReplayGuard = 4,
        DaemonSetup = 5,
        Output = 6,
        OwnerLaunch = 7,
        OwnerReceipt = 8,
        ResearchDirectoryMissing = 9,
        ResearchJournalMissing = 10,
        ResearchJournalRead = 11,
        ResearchSlot = 12,
        ResearchService = 13,
        Cleanup = 14,
        Log = 15,
        QuestionStorage = 16,
        Autonomous = 17,
        CheckedStorageReplay = 18,
        Worker = 19,
        Start = 20,
        Stop = 21,
        Status = 22,
        Listener = 23,
    }

    pub enum StartupFailure in 13 {
        LifelineClosed = 1,
        InstanceMismatch = 2,
        Cancelled = 3,
        Launch = 4,
        FrameLimit = 5,
    }

    pub(crate) enum ControlFailure in 14 {
        ReadDeadline = 1,
        Frame = 2,
        InstanceMismatch = 3,
        Socket = 4,
        WriteDeadline = 5,
        Write = 6,
    }

    pub(crate) enum Qualification in 15 {
        NoNewAcceptedSolutions = 1,
        Pending = 2,
        OptimizationUnresolved = 3,
        NoAmbiguousTrainingDecisions = 4,
        Promoted = 5,
        DevelopmentRegression = 6,
        AnchorRegression = 7,
        NoDevelopmentGain = 8,
        IncompleteTransfer = 9,
        TransferRegression = 10,
        NoTransferGain = 11,
    }

    pub(crate) enum GenerationOutcome in 16 {
        CertifiedProgram = 1,
        CertifiedCertificate = 2,
        Unresolved = 3,
        CompositionFailed = 4,
        CompositionLimit = 5,
        PrerequisiteCompositionFailed = 6,
        ConstructionFailed = 7,
        ConstructionLimit = 8,
        ProgramFailed = 9,
        CertificateFailed = 10,
        CertificateClosureLimit = 11,
        CertificateLimit = 12,
        SearchBudget = 13,
        FactLimit = 14,
        DefinitionLimit = 15,
        GraphLimit = 16,
        DefinitionCheckFailed = 17,
        ProviderFailed = 18,
    }

    pub(crate) enum AbortFailure in 17 {
        Clock = 1,
        SignalStop = 2,
        ChildExitedBeforeConfirmation = 3,
        StopUnconfirmed = 4,
        WaitAuthorityLost = 5,
        StopDeadline = 6,
        SessionUnconfirmed = 7,
        Kill = 8,
        Reap = 9,
    }

    pub(crate) enum AbortReaper in 18 {
        None = 1,
        WaitPid = 2,
        OwnedChild = 3,
    }

    pub(crate) enum AbortSession in 19 {
        Unknown = 1,
        Detached = 2,
        Inherited = 3,
    }
}

impl InputLimit {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::CliJsonAllocationBudgetOverflow => "CLI JSON allocation budget overflow",
            Self::CliJsonAllocationLimit => "CLI JSON allocation limit",
            Self::ArtifactByteLimit => "artifact byte limit",
            Self::CheckedClosureOperationCapacity => "checked closure operation capacity",
            Self::CheckpointHeaderCapacity => "checkpoint header capacity",
            Self::CheckpointRecordCapacity => "checkpoint record capacity",
            Self::CitedClosureDependencyCapacity => "cited closure dependency capacity",
            Self::CitedClosureOperationCapacity => "cited closure operation capacity",
            Self::DependencyCountLimit => "dependency count limit",
            Self::EmptyCertificate => "empty certificate",
            Self::InventoryPageLimit => "inventory page limit",
            Self::InventoryPageLimitMustBePositive => "inventory page limit must be positive",
            Self::ProgramClosureDependencyCapacity => "program closure dependency capacity",
            Self::StagedCertificateByteCapacity => "staged certificate byte capacity",
            Self::StagedClosureByteOverflow => "staged closure byte overflow",
            Self::StagedClosureDependencyCapacity => "staged closure dependency capacity",
            Self::StagedClosureObjectOverflow => "staged closure object overflow",
            Self::StagedClosureResourceCapacity => "staged closure resource capacity",
            Self::StagedClosureStepOverflow => "staged closure step overflow",
            Self::StagedClosureStepWorkLimit => "staged closure step work limit",
            Self::TrainingDiagnosticPageLimit => "training diagnostic page limit",
            Self::TrainingQuestionPageLimit => "training question page limit",
            Self::TrainingSelectionPageLimit => "training selection page limit",
            Self::TrainingSuitePageLimit => "training suite page limit",
        }
    }
}
