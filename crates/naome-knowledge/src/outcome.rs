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
            // The checker owns the question prefilter domains.
            assert!(Domain::$name as u16 != 33 && Domain::$name as u16 != 34 && Domain::$name as u16 != 35 && Domain::$name as u16 != 37 && Domain::$name as u16 != 40 && Domain::$name as u16 != 41 && !(Domain::$name as u16 >= 45 && Domain::$name as u16 <= 56));
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
        WorkOfferUnavailable = 13,
        WorkOfferCapacity = 14,
        UnknownWorkOffer = 15,
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
        Stale = 9,
        Recorded = 10,
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
        Formula = 18,
        CheckedContext = 19,
        QuestionRegistration = 20,
    }

    pub enum InputFault in 7 {
        DescriptionAddressMismatch = 1,
        ArtifactCompatibilityMismatch = 2,
        CheckedIdentityMismatch = 3,
        MalformedJson = 4,
        CommandFrameLimit = 5,
        CommandFrameIncomplete = 6,
        CommandRead = 7,
        IdentityWidth = 8, HexWidth = 9, HexNoncanonical = 10,
        PrerequisiteDuplicate = 11, PrerequisiteProgramInvalid = 12,
        PrerequisiteOfferedProofMissing = 13,
        PrerequisiteNotClosed = 14, PrerequisiteObligationMissing = 15,
        RegularFileRequired = 16,
        RelayListenAddress = 17,
        RelayExternalAddress = 18,
        FormalGoalRequiresNative = 19,
        QuestionRegistryPopulated = 20,
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
        PrerequisiteObjectCapacity = 25,
        PrerequisiteArtifactBytes = 26,
        PrerequisiteBytesOverflow = 27,
        PrerequisiteByteCapacity = 28,
        PrerequisiteStepsOverflow = 29,
        PrerequisiteCheckerCapacity = 30,
        PrerequisiteDefinitionCapacity = 31,
        BoundedFileBytes = 32,
        RelayAddressCapacity = 33,
        ConfiguredPeers = 34,
        ProducerQueue = 35,
    }

    pub enum WorkerFailure in 9 {
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
        GrantEncoding = 31,
        ModelLength = 33,
        ProgramCapacity = 34,
        ProgramEncoding = 35,
        ResultInvalid = 36,
        FeedbackMeasurement = 37,
        FeedbackSequence = 38,
        FeedbackCheckpoint = 39,
        OutputDrainDeadline = 40,
        SupervisorExit = 41,
        GrantClosed = 42,
        GrantDecoding = 43,
        GrantIdentity = 44,
        ProgramUnsupported = 45,
        LearningUnsupported = 46,
        DescendantExecutable = 47,
        DescendantSpawn = 48,
        DescendantOutput = 49,
        DescendantRead = 50,
        DescendantIdentity = 51,
        HistoryUnsupported = 52,
        ModelReadUnsupported = 53,
        ModelWriteUnsupported = 54,
        HistoryReceiptMissing = 55,
        HistoryReceiptDecoding = 56,
        ModelResponseMissing = 57,
    }
    pub enum LearningGraphFailure in 10 {
        Capacity = 1,
        ActionArity = 2,
        BoundIndexWidth = 3,
        DanglingBoundVariable = 4,
        DecisionCapacity = 5,
        MissingExpert = 6,
        MissingPremise = 7,
        EmptyBatch = 8,
        BatchCapacity = 9,
        NodeBinding = 10,
        NodeOperandOrSymbol = 11,
        SuccessfulActionBinding = 12,
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
        TrainingRequestRead = 34,
        TrainingRequestMissing = 35,
        TrainingRequestParse = 36,
        TrainingResponseWrite = 37,
        DeveloperIdentityCreate = 38,
        DeveloperIdentityEncode = 39,
        DeveloperIdentityWrite = 40,
        BoundedFileOpen = 43,
        BoundedFileMetadata = 44,
        BoundedFileRead = 45,
        NetworkConfigParse = 46,
        RelaySignal = 47,
        RelayConfigParse = 48,
        RelayIdentity = 49,
        RelayDiscovery = 50,
        RelayTransport = 51,
        RelayBehaviour = 52,
        RelayListener = 53,
        PublicationRecoveryTarget = 54,
        QuestionMarkerRead = 55,
        QuestionCheckpointOpen = 56,
        QuestionCheckpointHeader = 57,
        QuestionRegistryMissing = 58,
        QuestionRegistryCompatibility = 59,
        QuestionMarkerWrite = 60,
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
        WorkgroupJoined = 108,
        WorkgroupYielded = 109,
        WorkgroupMember = 110,
        WorkgroupReceipt = 111,
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
        WorkOffer = 17,
        WorkStatus = 18,
    }

    pub(crate) enum DiscoveryQuery in 27 { Participants = 1, Announce = 2, Addresses = 3, Routing = 4 }

    pub(crate) enum CustodyFrame in 28 { AbortCompletion = 1, ChildCustody = 2 }

    pub(crate) enum JobState in 29 {
        Queued = 1, Running = 2, Suspended = 3, Complete = 4,
        Failed = 5, Cancelled = 6, Expired = 7, InDoubt = 8,
    }

    pub(crate) enum SelectionResult in 30 {
        NotRun = 1, Accepted = 2, Rejected = 3, ProviderFailed = 4, TimedOut = 5, Stale = 6,
    }

    pub enum ComputationState in 31 { Stopped = 1, Running = 2, Pausing = 3, Paused = 4 }

    pub enum ArtifactVerification in 32 { Checked = 1, NotRun = 2 }

    pub(crate) enum EventReason in 38 {
        ProviderEffectsOrCleanupUncertain = 1,
        CheckedPrerequisiteNotRetained = 2,
        AdmissionDeliveryUncertain = 3,
    }

    pub(crate) enum DialStage in 39 { Request = 1, Transport = 2 }

    pub(crate) enum FormatReasonCode in 42 {
        EmptyCertificate = 1, Limit = 2, ReferenceNotEarlier = 3, UnexpectedEnd = 4,
        UnknownTag = 5, Formula = 6, TrailingBytes = 7, Unsupported = 8,
        ZeroRelationArity = 9, ZeroFunctionArity = 10, DefinitionReference = 11,
        UndeclaredFormalVariable = 12, MissingFormalVariable = 13,
    }
    pub enum FormatResource in 43 { Steps = 1, Bytes = 2, Nodes = 3, Arity = 4 }
    pub enum FormatTagClass in 44 { ProofStep = 1, ZfcAxiom = 2, ArtifactPayload = 3, DefinitionKind = 4 }

    pub(crate) enum SelectionPurpose in 57 { Assessment = 1, Admission = 2, Initial = 3, Final = 4, Publication = 5 }

    pub(crate) enum ExperimentStatus in 58 { NotReady = 1, ResourcePaused = 2, FrozenSolver = 3, ScheduledNoUpdate = 4, Complete = 5, Interrupted = 6, BudgetExhausted = 7 }
    pub(crate) enum ExperimentReason in 59 { ColdParentUnqualified = 1, ContinuationUnavailable = 2, ParentAbsent = 3 }

    pub(crate) enum FinderLearningOutcome in 60 { CheckedResolution = 1, UnresolvedSearch = 2 }
    pub(crate) enum FinderEvidenceOutcome in 61 { Candidate = 1, NoCandidate = 2, Rejected = 3, Failed = 4, Expired = 5, InDoubt = 6 }

    pub(crate) enum TrainingOutcome in 62 { Verified = 1, Exhausted = 2, Unavailable = 3 }

    pub(crate) enum FixtureResult in 63 { Pass = 1, Fail = 2, Running = 3 }

    pub(crate) enum RelayEventKind in 64 { ReservationAccepted = 1, ReservationDenied = 2, ReservationClosed = 3, ReservationTimedOut = 4, CircuitDenied = 5, CircuitAccepted = 6, CircuitClosed = 7 }
    pub(crate) enum RelayStatus in 65 { Ok = 1, ReservationRefused = 2, ResourceLimitExceeded = 3, PermissionDenied = 4, ConnectionFailed = 5, NoReservation = 6, MalformedMessage = 7, UnexpectedMessage = 8 }
    pub(crate) enum IoFaultKind in 66 { NotFound = 1, PermissionDenied = 2, ConnectionRefused = 3, ConnectionReset = 4, ConnectionAborted = 5, NotConnected = 6, BrokenPipe = 7, TimedOut = 8, Interrupted = 9, UnexpectedEof = 10, Other = 11 }
    pub(crate) enum ServiceRole in 67 { Relay = 1 }

    pub(crate) enum ConnectionEndpoint in 68 { Dialer = 1, Listener = 2 }
    pub(crate) enum ConnectionPort in 69 { New = 1, Reused = 2 }
    pub(crate) enum ConnectionClose in 70 { Io = 1, KeepAliveTimeout = 2 }
    pub(crate) enum RelayClientEvent in 71 { ReservationAccepted = 1, OutboundCircuit = 2, InboundCircuit = 3 }

    pub enum ResearchFailure in 36 {
        ClockBeforeEpoch = 1, ClockOverflow = 2, ClockRollback = 3,
        ElapsedOverflow = 4, AccountingRecordMissing = 5,
        MultipleFailures = 6, EffectsUnconfirmed = 7, DriverPanic = 8,
        StopReceiptUnavailable = 9, OwnerThreadPanic = 10, OwnerRuntimeUnavailable = 11,
        OwnerCancelled = 12, WorkBudgetExhausted = 13, DuplicateProgram = 14,
        ReservationMissing = 15, ReservationSequence = 16, ProgressMissing = 17,
        ProgressNotRunning = 18, ProgressSequence = 19, LearningCheckpointMissing = 20,
        LearningReservation = 21, LearningSnapshotMissing = 22,
        ProgramJobMissing = 23, ProgramReservation = 24,
        ExperienceJournalRecordIdentityDiffers = 25,
        ExperiencePageIoOverflow = 26,
        ExperienceRecordExceedsTheWorkingPageCapacity = 27,
        HistoricalAdmittedSourceRecordMissing = 28,
        HistoricalOwnAdmissionIdentityDiffers = 29,
        HistoricalOwnAdmissionReceiptMissing = 30,
        HistoricalPageImmutableChunkDiffers = 31,
        HistoricalPeerProvenanceDiffers = 32,
        HistoricalPeerReceiptMissing = 33,
        HistoricalSourceExceedsWorkingPageCapacity = 34,
        HistoricalSourceIdentityDiffers = 35,
        HistoricalSourceRoleDiffers = 36,
        HistoricalSourceSolutionMissing = 37,
        HistoryIoOperationOverflow = 38,
        HistoryIoOverflow = 39,
        HistoryJobMissing = 40,
        HistoryLifetimeIoOverflow = 41,
        HistoryNativeOwnerMissing = 42,
        HistoryOriginalJobMissing = 43,
        HistoryReadLacksItsOriginalTrainingReservation = 44,
        HistorySourceHasNoJob = 45,
        NativeCheckpointWritesRequireTheReservedTrainingRole = 46,
        NativeModelIoLacksOriginalReservation = 47,
        NativeModelIoOperationsOverflow = 48,
        NativeModelIoOverflow = 49,
        NativeModelArtifactCountExhausted = 50,
        NativeModelChunkLengthDiffers = 51,
        NativeModelChunkMissing = 52,
        NativeModelImmutableChunkDiffers = 53,
        NativeModelLifetimeIoAllowanceExhausted = 54,
        NativeModelOriginalJobMissing = 55,
        NativeModelOriginalSnapshotMissing = 56,
        NativeModelReadOutsideImmutableOwnedSnapshots = 57,
        NativeModelRetainedChunkLengthDiffers = 58,
        ProviderProgramOriginalJobMissing = 59,
        ProviderProgramOriginalReservationMissing = 60,
        ResumedProviderProgramGroupDiffers = 61,
        ModelBlobCapacity = 62, ModelChunkIndex = 63, ModelChunkRange = 64,
        HistoryRecordKeySyntax = 65, HistoryRecordKeyEncoding = 66,
        HistoryRequestJobMissing = 67, HistoryPageRequestMismatch = 68,
        HistoryCursorNotAdvanced = 69,
        StatelessRankerMemory = 70,
        MemoryActionIndex = 71,
        MemoryTensorDecode = 72,
        MemorySuccessor = 73,
        MemoryCheckpointMissing = 74,
        MemoryShapeOrValue = 75,
        MemoryContext = 76,
        MemoryPrediction = 77,
        StatelessExplorationMemory = 78,
        InvalidActionScores = 79,
        FormulaCacheBatchCapacity = 80,
        FormulaCacheTensorDecode = 81,
        ScopeInvalidScores = 82,
        ScopeLemmaNotClosed = 83,
        ScopeBinderCapacity = 84,
        OfferedProofMissing = 85,
        OfferedProofBinding = 86,
        OfferedProofFormulaMissing = 87,
        LearningUnitSequence = 88,
        TrainingPlanMissing = 89,
        SampledSequenceOverflow = 90,
        MetaTrialPlanMissing = 91,
        NativeModelHashMismatch = 92,
        HistoryOriginEvidence = 93,
        HistoryTrajectoryMissing = 94,
        HistoryPageIdentity = 95,
        HistoryPageCursor = 96,
        HistoryPageContinuation = 97,
        HistoryRecordPageMismatch = 98,
        HistoryObservationHorizon = 99,
        HistorySourcePageLane = 100,
        HistorySourcePageMismatch = 101,
        HistoryPreparedCapacity = 102,
        HistoryPreparedIdentity = 103,
        HistoryPreparedChanged = 104,
        ExpectedProofArtifact = 105,
        NativeProgramBinding = 106,
        NativeCertificateConclusion = 107,
        NativeDefinitionHelpers = 108,
        NativeSourceIdentity = 109,
    }

}

pub(crate) fn io_fault_kind(error: &std::io::Error) -> crate::outcome::IoFaultKind {
    use crate::outcome::IoFaultKind as Code;
    use std::io::ErrorKind;
    match error.kind() {
        ErrorKind::NotFound => Code::NotFound,
        ErrorKind::PermissionDenied => Code::PermissionDenied,
        ErrorKind::ConnectionRefused => Code::ConnectionRefused,
        ErrorKind::ConnectionReset => Code::ConnectionReset,
        ErrorKind::ConnectionAborted => Code::ConnectionAborted,
        ErrorKind::NotConnected => Code::NotConnected,
        ErrorKind::BrokenPipe => Code::BrokenPipe,
        ErrorKind::TimedOut => Code::TimedOut,
        ErrorKind::Interrupted => Code::Interrupted,
        ErrorKind::UnexpectedEof => Code::UnexpectedEof,
        _ => Code::Other,
    }
}

/// A worker or owner failure code, restricted to outcomes valid for a job.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub(crate) struct JobFailureCode(std::num::NonZeroU32);

impl JobFailureCode {
    pub(crate) fn from_owner(error: &crate::Error) -> Self {
        Self::try_from(error.code()).expect("owner error must use a registered job failure code")
    }
}
impl From<WorkerFailure> for JobFailureCode {
    fn from(error: WorkerFailure) -> Self {
        Self(std::num::NonZeroU32::new(error.into()).expect("worker failure code is nonzero"))
    }
}
impl From<JobFailureCode> for u32 {
    fn from(error: JobFailureCode) -> Self {
        error.0.get()
    }
}
impl TryFrom<u32> for JobFailureCode {
    type Error = &'static str;
    fn try_from(code: u32) -> Result<Self, Self::Error> {
        if EvidenceCode::try_from(code).is_ok()
            || DurabilityCode::try_from(code).is_ok()
            || OperationCode::try_from(code).is_ok()
            || InputFault::try_from(code).is_ok()
            || InputLimit::try_from(code).is_ok()
            || WorkerFailure::try_from(code).is_ok()
            || LearningGraphFailure::try_from(code).is_ok()
            || RuntimeFailure::try_from(code).is_ok()
            || StartupFailure::try_from(code).is_ok()
            || ResearchFailure::try_from(code).is_ok()
        {
            Ok(Self(
                std::num::NonZeroU32::new(code).expect("registered code is nonzero"),
            ))
        } else {
            Err("unknown job failure code")
        }
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
            Self::PrerequisiteObjectCapacity => "prerequisite object capacity",
            Self::PrerequisiteArtifactBytes => "prerequisite artifact byte capacity",
            Self::PrerequisiteBytesOverflow => "prerequisite byte overflow",
            Self::PrerequisiteByteCapacity => "prerequisite byte capacity",
            Self::PrerequisiteStepsOverflow => "prerequisite step overflow",
            Self::PrerequisiteCheckerCapacity => "prerequisite checker capacity",
            Self::PrerequisiteDefinitionCapacity => "prerequisite definition capacity",
            Self::BoundedFileBytes => "bounded file byte limit",
            Self::RelayAddressCapacity => "relay advertised address capacity",
            Self::ConfiguredPeers => "configured peer capacity",
            Self::ProducerQueue => "producer queue capacity",
        }
    }
}

#[cfg(all(test, feature = "developer-tools"))]
mod catalog_tests {
    #[test]
    fn combined_catalog_has_unique_nonzero_codes() {
        let codes: Vec<_> = crate::outcome_codes().map(|(_, _, code)| code).collect();
        let unique: std::collections::BTreeSet<_> = codes.iter().copied().collect();
        assert!(!unique.contains(&0));
        assert_eq!(unique.len(), codes.len());
        assert!(unique.contains(&naome_checker::question::RejectionReason::KnownProof.code()));
        assert!(unique.contains(&naome_checker::question::PrefilterOutcome::Inconclusive.code()));
    }
}

#[cfg(test)]
mod job_failure_tests {
    use super::*;

    #[test]
    fn fixture_result_codes_match_evidence_contract() {
        assert_eq!(u32::from(FixtureResult::Pass), 0x003f_0001);
        assert_eq!(u32::from(FixtureResult::Fail), 0x003f_0002);
        assert_eq!(u32::from(FixtureResult::Running), 0x003f_0003);
    }

    #[test]
    fn experiment_outcomes_use_distinct_registered_codes() {
        let result = serde_json::json!({
            "status": ExperimentStatus::Interrupted,
            "reason": ExperimentReason::ContinuationUnavailable,
        });
        assert_eq!(result["status"], 0x003a_0006_u32);
        assert_eq!(result["reason"], 0x003b_0002_u32);
        assert_eq!(
            serde_json::from_value::<ExperimentStatus>(result["status"].clone()).unwrap(),
            ExperimentStatus::Interrupted
        );
        assert!(serde_json::from_value::<ExperimentReason>(0x003b_ffff_u32.into()).is_err());
    }

    #[test]
    fn event_context_codes_round_trip_and_reject_unknown_values() {
        let event = serde_json::json!({
            "reason": EventReason::AdmissionDeliveryUncertain,
            "stage": DialStage::Transport,
        });
        assert_eq!(event["reason"], 0x0026_0003_u32);
        assert_eq!(event["stage"], 0x0027_0002_u32);
        assert_eq!(
            serde_json::from_value::<EventReason>(event["reason"].clone()).unwrap(),
            EventReason::AdmissionDeliveryUncertain
        );
        assert!(serde_json::from_value::<DialStage>(0x0027_ffff_u32.into()).is_err());
    }

    #[test]
    fn job_failure_codes_preserve_owner_and_worker_domains() {
        assert_eq!(
            std::mem::size_of::<Option<JobFailureCode>>(),
            std::mem::size_of::<u32>()
        );
        for error in [
            crate::Error::Research(ResearchFailure::WorkBudgetExhausted),
            crate::Error::MemoryOverload {
                requested: 3,
                charged: 4,
                budget: 5,
            },
            crate::Error::Runtime(RuntimeFailure::ResearchJournalRead),
        ] {
            let failure = JobFailureCode::from_owner(&error);
            assert_eq!(u32::from(failure), error.code());
            assert_eq!(
                serde_json::from_value::<JobFailureCode>(error.code().into()).unwrap(),
                failure
            );
        }
        let worker = JobFailureCode::from(WorkerFailure::FrameTruncated);
        assert_eq!(u32::from(worker), u32::from(WorkerFailure::FrameTruncated));
        assert!(
            serde_json::from_value::<JobFailureCode>(u32::from(NodeEvent::Starting).into())
                .is_err()
        );
        assert!(serde_json::from_value::<JobFailureCode>(u32::MAX.into()).is_err());
    }
}
