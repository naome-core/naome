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
        CheckedContext = 19,
    }

    pub enum InputFault in 7 {
        DescriptionAddressMismatch = 1,
        ArtifactCompatibilityMismatch = 2,
        CheckedIdentityMismatch = 3,
        MalformedJson = 4,
        CommandFrameLimit = 5,
        CommandFrameIncomplete = 6,
        CommandRead = 7,
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
        Clock = 12,
        ResourceSnapshot = 13,
        SupervisorExecutable = 14,
        StartEncoding = 15,
        SpawnLock = 16,
        SlotInheritance = 17,
        SupervisorSpawn = 18,
        SupervisorIdentity = 19,
        LifelineUnavailable = 20,
        OutputUnavailable = 21,
        PipeIo = 22,
        FrameTruncated = 23,
        FrameCapacity = 24,
        StreamCapacity = 25,
        FrameEncoding = 26,
        FrameIdentity = 27,
        CheckpointOverflow = 28,
        OwnerUnavailable = 29,
        OwnerRejected = 30,
        GrantEncoding = 31,
        ModelRange = 32,
        ModelLength = 33,
        ProgramCapacity = 34,
        ProgramEncoding = 35,
        ResultInvalid = 36,
        FeedbackMeasurement = 37,
        FeedbackSequence = 38,
        FeedbackCheckpoint = 39,
        OutputDrainDeadline = 40,
        SupervisorExit = 41,
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
        HolePunchFailed = 40,
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
        QuestionBacklog = 24,
        QuestionAcknowledgement = 25,
        QuestionSelection = 26,
        QuestionRetention = 27,
        QuestionDelivery = 28,
        AutonomousReceipt = 29,
        AutonomousArchive = 30,
        AutonomousFinding = 31,
        AutonomousSolving = 32,
        AutonomousCursor = 33,
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
    pub(crate) enum AdmissionFailure in 20 {
        PrerequisitesNotRetained = 1,
        InFlightPrerequisites = 2,
        ArchivedPrerequisites = 3,
        DuplicateWaiterCapacity = 4,
        DiskReservation = 5,
        ResultReservation = 6,
        QueueCapacity = 7,
        CursorConsumed = 8,
        InFlightUncertain = 9,
        AccountUncertain = 10,
        AllowanceExpired = 11,
    }
    pub(crate) enum WorkerFrame in 21 {
        History = 1,
        Model = 2,
        Learning = 3,
        Feedback = 4,
        Ready = 5,
        Descendant = 6,
        CpuActive = 7,
        CpuDone = 8,
        ResultReady = 9,
        Reserve = 10,
        Program = 11,
        Progress = 12,
        Result = 13,
        Failed = 14,
        Uncertain = 15,
        CleanupComplete = 16,
        CleanupFailed = 17,
    }

    pub enum IngestStatus in 22 {
        Accepted = 1,
        Duplicate = 2,
        Waiting = 3,
        WaitingDuplicate = 4,
    }
    pub(crate) enum NodeEvent in 23 {
        Accepted = 1,
        AdaptiveConfirmation = 2,
        AdaptiveRoundCompleted = 3,
        Announcement = 4,
        Bounded = 5,
        CandidateCacheRetirementDeferred = 6,
        CommandError = 7,
        CommandInputClosed = 8,
        Connected = 9,
        ContactExpired = 10,
        ControlRejected = 11,
        DhtParticipant = 12,
        DhtQuery = 13,
        DialFailed = 14,
        Disconnected = 15,
        Discovered = 16,
        DiscoveryRejected = 17,
        ExchangeRequest = 18,
        ExchangeResponse = 19,
        ExternalCandidate = 20,
        ExternalConfirmed = 21,
        ExternalExpired = 22,
        FatalError = 23,
        FinderCheckedInputs = 24,
        FinderGoalSupported = 25,
        FinderLearned = 26,
        FinderSelected = 27,
        FinderStudyRound = 28,
        HolePunchAttempt = 29,
        HolePunchResult = 30,
        Identified = 31,
        InboundFailed = 32,
        IncomingConnectionFailed = 33,
        IncompatiblePeer = 34,
        Ingest = 35,
        InventoryPage = 36,
        InventoryUnchanged = 37,
        LemmaLoopUnavailable = 38,
        MatchedRecursiveComplete = 39,
        MatchedRecursiveGoal = 40,
        MdnsExpired = 41,
        NativeCurriculumSelected = 42,
        NativeDataGeneration = 43,
        NativeDefinitionObserved = 44,
        NativeLearningQualification = 45,
        NativeMetaPlan = 46,
        NativeMetaUpdated = 47,
        NativePeerReplay = 48,
        NativeProgramChecked = 49,
        NativeTheoremObserved = 50,
        ObservedLargeContextResolved = 51,
        OfferResult = 52,
        OuterMetaTrialCompleted = 53,
        OwnAdmissionFailed = 54,
        OwnSearchCompleted = 55,
        OwnSearchStarted = 56,
        PeerError = 57,
        PreservationBranchCompleted = 58,
        ProducerDeferred = 59,
        ProducerRejected = 60,
        ProducerResult = 61,
        ProgramChunkRejected = 62,
        ProgramTransferDeferred = 63,
        ProofBacklogDeferred = 64,
        ProofBacklogError = 65,
        ProofBacklogOverload = 66,
        ProofCandidateDeferred = 67,
        ProofCandidateRejected = 68,
        ProofDeferred = 69,
        ProofGenerated = 70,
        ProofSkipped = 71,
        ProviderHint = 72,
        PublicationExpired = 73,
        PublicationRetryLimit = 74,
        QuestionAssessed = 75,
        QuestionCandidateRejected = 76,
        QuestionGenerated = 77,
        QuestionProviderFailed = 78,
        QuestionRecoveryHold = 79,
        Ready = 80,
        Rejected = 81,
        RelayAdvertised = 82,
        RelayClient = 83,
        RelayConnected = 84,
        RelayListenFailed = 85,
        RelayService = 86,
        RelayStarting = 87,
        RequestFailed = 88,
        ResearchCreated = 89,
        ResearchDescendant = 90,
        ResearchFinished = 91,
        ResearchReaped = 92,
        ResearchRecoveryHold = 93,
        ResearchServiceFailed = 94,
        ResearchStarted = 95,
        ResearchWorker = 96,
        ResearchWorking = 97,
        ResourceObservation = 98,
        Response = 99,
        RetiredListenerError = 100,
        ShutdownFailed = 101,
        SolveCancelledByAnswer = 102,
        SolveObligationHeldOrExpired = 103,
        Starting = 104,
        StartupReplay = 105,
        Stopped = 106,
        StorageError = 107,
    }
    pub(crate) enum EventSource in 24 {
        Fetch = 1,
        LocalPending = 2,
        Pending = 3,
        NativeSolver = 4,
        MockProducer = 5,
        Producer = 6,
        Local = 7,
        DeterministicProducer = 8,
        LocalBacklog = 9,
        LocalListener = 10,
        Mdns = 11,
        Identify = 12,
        Dht = 13,
    }

    pub(crate) enum StartupPhase in 25 { Begin = 1, Checked = 2 }

    pub(crate) enum MessageKind in 26 {
        Inventory = 1,
        InventoryResult = 2,
        InventoryUnchanged = 3,
        InventoryRestart = 4,
        Get = 5,
        Describe = 6,
        Description = 7,
        Object = 8,
        Offer = 9,
        Receipt = 10,
        Missing = 11,
        PeerError = 12,
        ProgramDescription = 13,
        ProgramOffer = 14,
        ProgramGet = 15,
        ProgramData = 16,
    }

    pub(crate) enum DiscoveryQuery in 27 { Participants = 1, Announce = 2, Addresses = 3, Routing = 4 }

    pub(crate) enum CustodyFrame in 28 { AbortCompletion = 1, ChildCustody = 2 }

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
