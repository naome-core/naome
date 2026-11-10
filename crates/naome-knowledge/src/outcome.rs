//! Numeric identifiers for machine outcomes exported by the node.
//! Each domain owns a disjoint range. Exported values are assigned explicitly.
macro_rules! codes {
    ($( $(#[$enum_attr:meta])* $visibility:vis enum $name:ident in $domain:literal { $($(#[$variant_attr:meta])* $variant:ident = $id:literal),+ $(,)? } )+) => {
        #[repr(u16)]
        enum Domain {
            $($name = $domain),+
        }
        $(codes!(@domain $(#[$enum_attr])* $visibility enum $name { $($(#[$variant_attr])* $variant = $id),+ });)+

        /// Domain, outcome name and canonical code for offline tooling.
        #[cfg(feature = "developer-tools")]
        pub const OUTCOME_CODES: &[(&str, &str, u32)] = &[
            $($( (stringify!($name), stringify!($variant), $name::$variant as u32), )+)+
        ];
    };
    (@domain $(#[$enum_attr:meta])* $visibility:vis enum $name:ident { $($(#[$variant_attr:meta])* $variant:ident = $id:literal),+ }) => {
        $(#[$enum_attr])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
        #[repr(u32)]
        #[serde(try_from = "u32", into = "u32")]
        $visibility enum $name {
            $($(#[$variant_attr])* $variant = ((Domain::$name as u32) << 16) | $id),+
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
        MissingQuestionDefinition = 7,
        ProofCheck = 8,
        DiagnosticInspection = 9,
        CertificateFormat = 10,
        InvalidStoredRecord = 11,
        QuestionLimit = 13,
        ExecutionFailed = 14,
        ProgramCodec = 15,
        QuestionInput = 16,
        ProgramInput = 17,
        Formula = 18,
        CheckedContext = 19,
        QuestionRegistration = 20,
        DefinitionCheck = 21,
        CheckpointDecode = 22,
        CheckpointSql = 23,
        StorageIo = 24,
        ResourceProfileDecode = 25,
        ResourceValidation = 26, CertificateConstruction = 27, DefinedFormula = 28, DefinitionExpansion = 29, Schema = 30, ProgramProjection = 31, Compression = 32, ProgramSql = 33, Io = 34, MissingRequiredTheorem = 35, CatalogSql = 36, BacklogSql = 37, CheckedIndexCloseSql = 38, StorageCombined = 39, CheckedIndexSql = 40, ConfigDecode = 41, ProofCommandInput = 42, ObservationUnavailable = 43, RecordDecode = 44, StartupChildExit = 45,
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
        InternalCutContext = 786, PrerequisiteOfferedProofMissing = 13,
        PrerequisiteNotClosed = 14, PrerequisiteObligationMissing = 15,
        RegularFileRequired = 16,
        RelayListenAddress = 17,
        RelayExternalAddress = 18,
        FormalGoalRequiresNative = 19,
        QuestionRegistryPopulated = 20,
        CheckpointRecordKey = 21,
        CheckpointRecordReadLimit = 22,
        CheckpointRecordDigest = 23,
        CheckpointPageBudget = 24,
        CheckpointPageByteWidth = 25,
        CheckpointPageRecordWidth = 26,
        CheckpointPageMemoryOverflow = 27,
        CheckpointPageMemoryLimit = 28,
        CheckpointFileReplaced = 29,
        CheckpointOutsideOwner = 30,
        CheckpointEncoding = 31,
        CheckpointNoncanonical = 32,
        CheckpointHeaderCardinality = 33,
        CheckpointHeaderDomain = 34,
        CheckpointHeaderCapacity = 35,
        CheckpointHeaderDigest = 36,
        CheckpointHeaderCount = 37,
        CheckpointIdentity = 38,
        CheckpointSchema = 39,
        CheckpointIntegrity = 40,
        CheckpointRowCount = 41,
        CheckpointCountWidth = 42,
        CheckpointReadWidth = 43,
        CheckpointUnexpectedKind = 44,
        CheckpointParentMissing = 45,
        CheckpointFilenameMissing = 46,
        CheckpointTargetExists = 47,
        OwnedFileType = 48,
        OwnedFileLinks = 49,
        OwnedFileOwner = 50,
        OwnedInputLimitWidth = 51,
        OwnedInputCapacity = 52,
        MarkerCorrupt = 53,
        MarkerParentMissing = 54,
        ResourceCustomInvalid = 55,
        ResourceCustomProfileMismatch = 56,
        ResourceEffectiveEncoding = 57,
        ResourceEffectiveCapacity = 58,
        ResourceEffectiveIdentity = 59,
        ResourceImmutable = 60,
        ResourceInitializationRace = 61,
        ResourceObservationDirectory = 62,
        ResearchCompatibility = 63, CooperativeRole = 64, EmptyTrainingEpoch = 65,
        PeerIdentitySyntax = 67, PeerIdentityEncoding = 68,
        RequiredTheorems = 69, PrerequisiteRoots = 70,
        ProgramReplyRoot = 71, ProgramReplyId = 72, ProgramReplyStart = 73,
        ProgramReplyEmpty = 74, ProgramReplyLimit = 75, ProgramDescriptionRoot = 76, ProgramDescriptionId = 77, StoredQuestionProofHeaderMissing = 78, StoredQuestionBinding = 79, CheckedStorageHaltPoisoned = 80, CheckedInventoryMismatch = 81, CatalogReplayCursorWidth = 82, CatalogReplayCursorBeyondCount = 83, CatalogReplayPageWidth = 84, CatalogReplayOrdinalOverflow = 85, CatalogReplayOrderIncomplete = 86, CatalogReplayPageCount = 87, CatalogReplayProofMissing = 88, CatalogReplayProofOrder = 89, CatalogProofIdOrdering = 90, CatalogChangedDuringReplay = 91, CatalogReplayRoot = 92, CatalogQuestionMemberMissing = 93, CatalogExternalChange = 94, CatalogNotValidated = 95, CatalogSchemaUnsupported = 96, CatalogSchemaObject = 97, CatalogSchemaMismatch = 98, CatalogSchemaIncomplete = 99, CatalogMetadataCardinality = 100, CatalogDatabaseIdentity = 101, CatalogActivationState = 102, CatalogActivationRoot = 103, CatalogInitialData = 104, CatalogValidationProofMissing = 105, CatalogPayloadCount = 106, CatalogNotActive = 107, CatalogSummaryMismatch = 108, CatalogPayloadLength = 109, CatalogPayloadDigest = 110, CatalogProofIdentity = 111, CatalogOriginMembership = 112, CatalogOriginCommitMissing = 113, CatalogDependencyOrder = 114, CatalogCorpusSummary = 115, CatalogRelationCount = 116, CatalogMembershipIncomplete = 117, CatalogDependencyMissing = 118, CatalogCommitRootMissing = 119, CatalogProofCollision = 120, CatalogCommitDigest = 121, CatalogForeignKeyMismatch = 122, CatalogFileType = 123, CatalogStageFileType = 124, CatalogStageNotEmpty = 125, CatalogPeerCursorWidth = 126, CatalogPeerOrdinalWidth = 127, CatalogPeerOriginSyntax = 128, CatalogPeerOrdinalMismatch = 129, CatalogPageCountWidth = 130, CatalogBatchCount = 131, CatalogBatchByteOverflow = 132, CatalogBatchByteCapacity = 133, CatalogBatchDuplicateProof = 134, CatalogBatchEmpty = 135, CatalogFilenameMissing = 136, CatalogJournalMode = 137, CatalogBusyTimeoutWidth = 138, CatalogFullSync = 139, CatalogCountWidth = 140, CatalogByteWidth = 141, CatalogReplayCountOverflow = 142, CatalogReplayCountWidth = 143, CatalogPayloadLengthWidth = 144, CatalogProofMemoryOverflow = 145, CatalogPayloadWidth = 146, CatalogCountOverflow = 147, CatalogByteOverflow = 148, CatalogSuccessorFingerprintMissing = 149, CatalogMetadataUpdateCount = 150, CatalogProofAlreadyOwned = 151, CatalogCommitPeerOrigin = 152, CatalogCommitMembership = 153, CatalogCommitProofMissing = 154, CatalogDependencyOrdering = 155, CatalogMembershipOrdering = 156, CatalogMembershipCountOverflow = 157, CatalogCommitCountWidth = 158, CatalogValidationCommitProofMissing = 159, CatalogProofOwnerMismatch = 160, CatalogRelationCountWidth = 161, CatalogIdentityWidth = 162, CatalogOrdinalWidth = 163, CatalogOrdinalZero = 164, CatalogIntegerWidth = 165, CatalogPageLimit = 166, CatalogActivatedMissing = 167, CatalogReceiptMissing = 168, CatalogStageAcceptedData = 169, CatalogGenerationPoisoned = 170, CatalogLockPoisoned = 171, CorpusLeafType = 172, CorpusLeafLinks = 173, CorpusReceiptInvalid = 174, CorpusReceiptWidth = 175, CorpusReceiptConflict = 176, CorpusReceiptType = 177, CorpusReceiptLinks = 178, CorpusReceiptChanged = 179, CatalogClock = 180, CatalogDirectoryOwned = 181, CatalogFileChanged = 182, CatalogProgramAddressExhausted = 183, CatalogProgramAddressNegative = 184, CatalogProgramStagingMissing = 185, CatalogProgramManifestChanged = 186, CatalogProgramPrefixExceeds = 187, CatalogProgramAddressMismatch = 188, CatalogProgramCursorBeyondPrefix = 189, CatalogProgramIdentityMismatch = 190, CatalogProgramInputOrdering = 191, CatalogProgramInputHash = 192, CatalogProgramStreamSuffix = 193, CatalogProgramStreamRoot = 194, CatalogProgramPrefixSummary = 195, CheckedIndexClosed = 196, CheckedIndexLockPoisoned = 197, CheckedCacheLockPoisoned = 198, CheckedWritePhaseActive = 199, CheckedWritePhaseMissing = 200, CheckedWriteBufferActive = 201, CheckedSourceBegin = 202, CheckedMirrorBegin = 203, CheckedSourceCommit = 204, CheckedMirrorCommit = 205, CheckedStartupPageUnavailable = 206, CheckedWriteGatePoisoned = 207, CheckedHaltLockPoisoned = 208, CheckedCopyMirrorAttached = 209, CheckedCopyTargetMirrors = 210, CheckedCopyEpochOverflow = 211, CheckedCopyRouteChanged = 212, CheckedAdmissionOwned = 213, CheckedAdmissionEpochMissing = 214, CheckedAdmissionOwnerChanged = 215, CheckedSourceGate = 216, CheckedMirrorGate = 217, CheckedCacheSizeWidth = 218, CheckedSuccessorBuffered = 219, CheckedGenerationOverflow = 220, CheckedStartupVacuumMode = 221, CheckedIndexSizeOverflow = 222, CheckedIndexSizeWidth = 223, CheckedPruneUnfinishedPage = 224, CheckedPruneVacuumMode = 225, CheckedPruneReclaimIncomplete = 226, CheckedIndexFileType = 227, CheckedIndexFileLinks = 228, DisposableIndexOwned = 229, DisposableIndexSequence = 230, DisposableIndexClock = 231, DisposableIndexParent = 232, DisposableIndexConnectionPoisoned = 233, DisposableIndexMirrorPoisoned = 234, DisposableIndexMirrorActive = 235, DisposableIndexClosed = 236, DisposableIndexSize = 237, DisposableIndexChanged = 238, RegistryCompactionSize = 239, RegistryCompactionWidth = 240, ResearchDirectoryInvalid = 241, ControlEndpointInvalid = 242, ControlFrameIncomplete = 243, ControlFrameLimit = 244, ControlReadTimeout = 245, ControlWriteTimeout = 246, ControlConnectTimeout = 247, ControlResponseMismatch = 248, ControlJsonIo = 249, ControlJsonSyntax = 250, ControlJsonData = 251, ControlJsonEof = 252, StopProcessGroupUnconfirmed = 253, StopProcessIdentity = 254, CandidateDirectoryInvalid = 255, CandidateChanged = 256, CandidateFormat = 257, CandidateLockChanged = 258, ProofWorkChanged = 259, ProofWorkFilename = 260, ProofBudgetEncoding = 261, ProofCacheBudget = 262, ProofWorkBudget = 263, ProbeCustodyPoisoned = 264, ProbeCustodyUnconfirmed = 265, ProbeCleanupPending = 266, ProbeDeadline = 267, ProbeOutputMissing = 268, ProbeCapacity = 269, ProbeExitFailure = 270, ProbeOutputEncoding = 271, ObservationNumeric = 272, ObservationCapacity = 273, ObservationProcessFormat = 274, ObservationProcessOverflow = 275, ObservationProcessDuplicate = 276, ObservationProcessMissing = 277, ObservationProcessCycle = 278, ObservationPlatformField = 279, ObservationCgroupMembership = 280, ObservationCgroupPath = 281, ObservationCgroupQuota = 282, ObservationIncomplete = 283, ObservationClock = 284, ObservationClockWidth = 285, CalibrationDescriptorReserve = 286, CalibrationMemoryReserve = 287, CalibrationCpuWidth = 288, NodeDirectoryInvalid = 289, CorpusCountWidth = 290, AcceptedCountOverflow = 291, LogRecordEncoding = 292, LogRecordCapacity = 293, LogFileInvalid = 294, LogPathInvalid = 295, RuntimeIntervalsWidth = 296, RuntimeConfigObject = 297, RuntimeConfigDirectory = 298, RuntimeConfigOwner = 299, RuntimeConfigProducer = 300, IdentityKeyMissing = 301, IdentityKeyEncode = 302, IdentityKeyDecode = 303, IdentityReceiptVersion = 304, IdentityReceiptMismatch = 305, IdentityReceiptMissing = 306, IdentityReceiptEncode = 307, RuntimeConfigEncode = 308, ControlNonceMissing = 309, ControlNonceInvalid = 310, ControlSocketPath = 311, ControlEndpointEncode = 312, ControlTaskCancelled = 313, ControlTaskFailed = 314, StartupDeadline = 315, StartupAcknowledgementDeadline = 316, StartupPidInvalid = 317, StartupReapUnconfirmed = 318, StartupAbortReport = 319, NodeDirectoryUnset = 320, NodeDirectoryEmpty = 321, LifecycleLockTimeout = 322, StartupHandoffExisting = 323, StartupLifelineMissing = 324, ResourceSnapshotEncoding = 325, RouteAddressBytes = 326, RouteEndpointInvalid = 327, RouteTargetInvalid = 328, ContactAllocationOverflow = 329, ContactRetired = 330, ContactSelf = 331, ContactCapacity = 332, ContactDisabled = 333, ContactPrivateAddress = 334, ContactDirectDisabled = 335, ContactAddressCapacity = 336, ContactPinnedCapacity = 337, ContactInboundDirectDisabled = 338, ContactInboundSender = 339, ContactLocalAddress = 340, RouteTargetRequired = 341, ContactStaticPolicy = 342, NetworkRelayPolicy = 343, NetworkRelayId = 344, NetworkRelayAddress = 345, NetworkBootstrapId = 346, NetworkBootstrapAddress = 347, NetworkPeerId = 348, NetworkPeerAddress = 349, NetworkDuplicatePeer = 350, NetworkListenAddress = 351, NetworkExternalAddress = 352, NetworkDirectAdvertisement = 353, DiscoveryProtocolInvalid = 354, DescriptionStatementMismatch = 355, StatementIdentityWidth = 356, CheckedConclusionMissing = 357, TransportTaskCancelled = 358, TransportTaskFailed = 359, CliArgumentsInvalid = 360, CliHandoffCommand = 361, StatusEncoding = 362, ReplayClockNegative = 363, ReplayClockOverflow = 364, ReplayRssNegative = 365, ReplayRssOverflow = 366, ReplayRssUnavailable = 367, ReplayDescriptor = 368, ReplayNonce = 369, ReplayCutoff = 370, ReplayWindow = 371, ReplayFrameLimit = 372, ReplayFrameEncoding = 373, ReplayGrantIdentity = 374, ReplaySequence = 375, ReplaySampleClock = 376, ReplayGrantOrder = 377, ReplayGrantExpired = 378, ReplayDeadline = 379, ReplayMemory = 380, ReplaySetting = 381, ReplayCommand = 382, ReplaySession = 383, ReplayInitialGrant = 384, ReplayLifelineClosed = 385, ReplayCallerGone = 386, ReplayFinalGrant = 387, ReplayWatcherPanicked = 388, HandoffEndpointMissing = 389, HandoffEndpointInvalid = 390, HandoffCleanupWindow = 391, HandoffPipeRequired = 392, HandoffActiveWindow = 393, HandoffDeadline = 394, HandoffEndpointOverflow = 395, HandoffLifelineClosed = 396, HandoffPrematureAck = 397, StartupSession = 398, StartupNonce = 399, StartupCustodyEndpoint = 400, StartupCustodyEncoding = 401, StartupCustodyExpired = 402, StartupBeginUnavailable = 403, StartupLifelineDeadline = 404, StartupParentClosed = 405, StartupFrameLimit = 406, StartupOwnerUnavailable = 407, StartupFrameMismatch = 408, QuestionAdmissionCount = 409, QuestionAdmissionIndex = 410, QuestionFifoSequence = 411, QuestionFifoMissing = 412, QuestionFifoBinding = 413, QuestionFifoCount = 414, QuestionIndexCardinality = 415, QuestionAdmittedMissing = 416, QuestionAdmittedIndex = 417, QuestionFifoExhausted = 418, QuestionBacklogMissing = 419, QuestionBacklogBinding = 420, QuestionCanonicalMismatch = 421, QuestionFirstAdmissionImmutable = 422, QuestionPreparedMissing = 423, QuestionDeliveryState = 424, QuestionRecordBinding = 425, QuestionFirstRecordBinding = 426, BacklogMissing = 427, BacklogHeader = 428, BacklogSequence = 429, BacklogIdentityIndex = 430, BacklogDependencyIndex = 431, BacklogCountOverflow = 432, BacklogEdgeOverflow = 433, BacklogCardinality = 434, BacklogCycleDeadline = 435, BacklogCycle = 436, BacklogSequenceExhausted = 437, BacklogPayloadMissing = 438, BacklogReadyUninitialized = 439, BacklogPageWidth = 440, BacklogReadyMissing = 441, BacklogRowCapacity = 442, BacklogEncode = 443, BacklogLockPoisoned = 444, ReplayOrdinalOverflow = 445, ReplayOrderIncomplete = 446, ReplayPayloadBytesOverflow = 447, ReplayDependencyMissing = 448, ReplayContextBytesOverflow = 449, ReplayCountWidth = 450, ReplayCountMismatch = 451, ReplayCorpusMismatch = 452, CompactionDiskOverflow = 453, CompactionDiskWidth = 454, ProducerArtifactBytes = 455, ProofBytes = 456, ProofIdentityCollision = 457, ArtifactInputTag = 458, FunctionWitnessMissing = 459, FunctionProofMissing = 460, FunctionConclusionMismatch = 461, PublicationDiskOverflow = 462, PublicationDiskWidth = 463, InventoryPageLimit = 464, CheckedMembershipMismatch = 465, CheckedDependencyMissing = 466, CheckedInventorySetMismatch = 467, StateOwnerPanicked = 468, TransportStreamEnded = 469, TransportEpochExhausted = 470, TransportOwnerUnavailable = 471, TransportEventsClosed = 472, NetworkListenerClosed = 473, IntakeParentMetadataMismatch = 474, IntakeMetadataMismatch = 475, IntakeProofGrantExpired = 476, IntakeProofUnrequested = 477, IntakeRootDeadline = 478, IntakeMetadataObsolete = 479, IntakeDecisionDeadline = 480, IntakeMetadataLeaseExpired = 481, IntakeShortGrantExpired = 482, IntakeManifestChanged = 483, IntakeProgramUnrequested = 484, IntakeSelectionQuestionMissing = 485, IntakeBatchMissing = 486, IntakeCitedProgramUnrequested = 487, IntakeCitedParentMissing = 488, IntakeDependencyDescriptionUnrequested = 489, IntakeDependencyChunkUnrequested = 490, IntakeDependencyCertificateUnrequested = 491, IntakeDefinitionMismatch = 492, IntakeCitedDescriptionUnrequested = 493, SelectionPending = 494, SelectionProvenanceChanged = 495, SelectionDeadline = 496, SelectionCancelled = 497, SelectionInitialDeclined = 498, SelectionQuestionMissing = 499, SelectionRootMismatch = 500, SelectionFinalMissing = 501, IntakeUnselectedProofDependency = 502, IntakeClosureCycle = 503, IntakeCitedManifestChanged = 504, IntakeRepresentationMismatch = 505, IntakeProofMismatch = 506, IntakeRootStatementMismatch = 507, IntakeStagedDefinitionMissing = 508, IntakeCitedCheckedProgramMissing = 509, IntakeReadyMemberMissing = 510, IntakeProgramClosureCycle = 511, IntakeArtifactHeader = 512, IntakeCertificateHeader = 513, IntakeCertificateHeaderWidth = 514, IntakePayloadTag = 515, TransferGrantBinding = 516, FinderOperandStatementWidth = 517, TrainingAllowanceZero = 518, TrainingTargetNotChecked = 519, TrainingKnowledgeMismatch = 520, TrainingPartitionMismatch = 521, TrainingProofTargetMismatch = 522, TrainingQuestionDuplicate = 523, TrainingDependencyOrder = 524, TrainingClosureUnchecked = 525, TrainingClosureBytesOverflow = 526, TrainingWorkingSetOverflow = 527, TrainingObjectMissing = 528, TrainingIdentityWidth = 529, TrainingClosureEmpty = 530, TrainingRootOtherSplit = 531, TrainingPriorMissingCurrent = 532, TrainingDevelopmentBinding = 533, TrainingDevelopmentQuestions = 534, TrainingComputeOverflow = 535, TrainingComparisonConditions = 536, TrainingComparisonQuestions = 537, TrainingComparisonBudget = 538, TrainingRequestEncoding = 539, TrainingClosureUnsupported = 540, TrainingClosureOtherSplit = 541, ObjectProgramFormat = 542, ObjectProgramManifest = 543, ObjectProgramStatement = 544, ObjectProofStatementMissing = 545, ObjectDefinitionStatement = 546, ObjectPayloadTag = 547, ObjectQuestionRoot = 548, ObjectObligationWitnessMissing = 549, ObjectBytesOverflow = 550, ObjectMemoryOverflow = 551, ObjectProgramIdentity = 552, ObjectProofIdentityWidth = 553, ObjectDependencyMetadata = 554, ObjectProofObligation = 555, ObjectProofNoncanonical = 556, ObjectObligationBinding = 557, ObjectArtifactIdMismatch = 558, ObjectDependencyCycle = 559, ObjectManifestMissing = 560, ObjectProgramBinding = 561, GeneratedRootMissing = 562, GeneratedInputCapacity = 563, GeneratedWorkOverflow = 564, GeneratedBytesOverflow = 565, GeneratedWorkCapacity = 566, GeneratedHelperCollision = 567, CheckedBatchOperationCapacity = 568, StagedRootMissing = 569, CommittedClosureIncomplete = 570, ExchangeQuestionRootMismatch = 571, CheckedBatchCountOverflow = 572, CheckedBatchBytesOverflow = 573, StagedObjectDuplicate = 574, CheckedContextCapacity = 575, CheckedProgramContextWidth = 576, StagedDependencyMissing = 577, StagedObjectUnrequested = 578, CatalogDigestCountWidth = 579, CatalogDigestMembership = 580, CatalogDigestPeerSyntax = 581, CatalogDigestPeerEncoding = 582, CatalogDigestOrder = 583, CatalogDigestMemberWidth = 584, CatalogDigestQuestionWidth = 585, CatalogDigestPayloadWidth = 586, CatalogDigestDependencyWidth = 587, CatalogDigestRootCount = 588, CatalogInventoryCountWidth = 589, CatalogInventoryOrder = 590, CatalogInventoryPageCount = 591, LearningPrerequisiteCycle = 592, LearningPrerequisiteBytes = 593, LearningPrerequisitePacketWidth = 594, LearningPrerequisiteCapacity = 595, LearningFormulaMemory = 596, LearningFormulaMissing = 597, LearningDefinitionMissing = 598, LearningDefinitionType = 599, LearningDefinitionObligation = 600, LearningPeerProgramMissing = 601, LearningPeerProgramChunk = 602, LearningPeerProgramCycle = 603, LearningPeerOperandMissing = 604, LearningPeerContextBytes = 605, LearningClosureCycle = 606, LearningClosureBytes = 607, LearningCertificateIdentity = 608, ProgramWorkDirectory = 609, ProgramWorkConsumed = 610, ProgramPrefixExceeds = 611, ProgramPrefixMismatch = 612, ProgramInputMismatch = 613, ProgramSealMissing = 614, ProgramPrefixOwned = 615, ProgramDependencyIncomplete = 616, ProgramFormulaGraphWidth = 617, DependencyAlreadyComplete = 618, DependencyDuplicate = 619, ProviderCompletionUnknown = 620, FindingCursorExhausted = 621, ResearchJobIdExhausted = 622, CommandMissing = 623, CommandAfterInvalid = 624, CommandArtifactMissing = 625, CommandObjectMissing = 626, CommandIdMissing = 627, CommandTestDisabled = 628, CommandMetadataMissing = 629, CommandTestCapacity = 630, CommandStaticDiscovery = 631, CommandPeersMissing = 632, CommandPeerUnconfigured = 633, CommandAnnounceUnaccepted = 634, CommandPeerMissing = 635, CommandPeerDisabled = 636, CommandTestProofLimit = 637, CommandExchangeUnsupported = 638, CommandCompatibilityType = 639, CommandUnknown = 640, CommandPeerInvalid = 641, ResponseRootMismatch = 642, QuestionSelectionStale = 643, QuestionFreshCheckFailed = 644, QuestionNoveltyMissing = 645, EvidenceExactSolutionMissing = 646, EvidenceGoalMissing = 647, CheckpointRemovalWidth = 648, ObservedTargetMismatch = 649, StateDuplicateProof = 650, StateDuplicateDerivation = 651, StateProofCollision = 652, StateDerivationCollision = 653, StateStatementCollision = 654, StateDuplicateDefinition = 655, StateDefinitionCollision = 656, StateProofDependencyMissing = 657, StateDefinitionDependencyMissing = 658, StateDefinitionObligationMissing = 659, StateOther = 660, CheckedAdmissionAborted = 661, EvidenceCandidateBinding = 662, CheckedCopyChanged = 663, IntakeQueuedMetadataExpired = 664, IntakeQueuedProgramExpired = 665, IntakeStagedCapacity = 666, IntakeQueuedRootDeadline = 667, CatalogPeerOriginEncoding = 668, CatalogPragmaSynchronous = 669, CatalogPragmaForeignKeys = 670, CatalogPragmaCacheSize = 671, CatalogPragmaTempStore = 672, CatalogPragmaMmapSize = 673, CatalogPragmaBusyTimeout = 674, CatalogPragmaTrustedSchema = 675, CatalogPragmaOther = 676, CatalogIntegrityFailure = 677, TrainingProgressBinding = 678, TrainingDiagnosticBudget = 679,
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
        ProducerQueue = 35, PeerCertificateCapacity = 36, PeerProgramCapacity = 37, NetworkDiscoveryCapacity = 38, IntakeDescriptionCapacity = 39, IntakeProgramDescriptionCapacity = 40,
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
        ModelResponseMissing = 57, NativeContractMissing = 58, NativeSnapshotMissing = 59, PeerProgressMissing = 60, NativeProgressMissing = 61, NativeFinalMissing = 62, NativeRoleMismatch = 63, MockTargetMissing = 64, NativeProviderRequired = 65,
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
        DnsCapacity = 41,
        DnsNoAddress = 42,
        TransportAddressUnsupported = 43,
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
        StopReleaseUnconfirmed = 61,
        NetworkGossipConfig = 62, NetworkGossipBehaviour = 63, NetworkGossipSubscribe = 64, NetworkTransport = 65, NetworkRelayTransport = 66, NetworkBehaviour = 67, NetworkListener = 68, DiscoveryMdns = 69, StartupAbortReport = 70,
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
        ResourceObservationFailure = 112,
        ResearchCleanupFailed = 113,
        ResearchValueDecision = 114,
        ResearchValueObserved = 115,
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
    pub enum IoFaultKind in 66 { NotFound = 1, PermissionDenied = 2, ConnectionRefused = 3, ConnectionReset = 4, ConnectionAborted = 5, NotConnected = 6, BrokenPipe = 7, TimedOut = 8, Interrupted = 9, UnexpectedEof = 10, Other = 11, AlreadyExists = 12, InvalidInput = 13, InvalidData = 14, AddrInUse = 15, AddrNotAvailable = 16, WriteZero = 17, Unsupported = 18, NotADirectory = 19, IsADirectory = 20, DirectoryNotEmpty = 21, ReadOnlyFilesystem = 22 }
    pub(crate) enum ServiceRole in 67 { Relay = 1 }

    pub(crate) enum ConnectionEndpoint in 68 { Dialer = 1, Listener = 2 }
    pub(crate) enum ConnectionPort in 69 { New = 1, Reused = 2 }
    pub(crate) enum ConnectionClose in 70 { Io = 1, KeepAliveTimeout = 2 }
    pub(crate) enum RelayClientEvent in 71 { ReservationAccepted = 1, OutboundCircuit = 2, InboundCircuit = 3 }
    pub(crate) enum DefinitionCheckReason in 72 { Expansion = 1, CanonicalBody = 2, Certificate = 3, UnknownObligation = 4, ObligationMismatch = 5, ObligationFormula = 6, Unsupported = 7 }
    pub enum JsonFault in 73 { Io = 1, Syntax = 2, Data = 3, Eof = 4 }
    pub enum SqlFault in 74 { Engine = 1, MissingRow = 2, ColumnType = 3, Other = 4 }
    pub enum SchemaFailure in 79 { RoleCollision = 1, ParameterRoleCollision = 2, DuplicateParameter = 3, ForbiddenPredicateVariable = 4, UndeclaredPredicateVariable = 5 }
    pub enum ResourceValidationReason in 78 {
        ProfileVersion = 1, MemoryBudget = 2, ScalingOverflow = 3, FieldWidth = 4,
        ResidentOverflow = 5, FieldBudget = 6, FieldZero = 7, Timer = 8,
        Custody = 9, Workers = 10, CheckerCache = 11, CountBudget = 12,
        BufferBudget = 13, ContactOverflow = 14, ContactConfiguration = 15,
        ProviderOverflow = 16, TransportOverflow = 17, RetainedOverflow = 18,
        IndexOverflow = 19, QueueOverflow = 20, AllocationOverflow = 21,
        AllocationBudget = 22, LimitsInconsistent = 23, IdentifySafety = 24,
        AssessmentCapacity = 25, NativeModelLimits = 26, NativeModelAllocation = 27,
        DiskVolumeChanged = 28, DiskReservationLock = 29, DiskReservationOverflow = 30,
    }
    #[derive(Default)]
    pub enum AdaptiveProfile in 76 { #[default] Dynamic = 1, Heavy = 2, Light = 3, Custom = 4 }
    pub enum StorageIoOperation in 75 { CreateStage = 1, ResolveParent = 2, SyncStage = 3, Publish = 4, SyncParent = 5, InspectOwnedFile = 6, OpenInput = 7, InspectInput = 8, ReadInput = 9, CreateMarker = 10, WriteMarker = 11, SyncMarker = 12, SyncMarkerParent = 13, CurrentDirectory = 14, ResolveResourceProfile = 15, InspectDiskVolume = 16, InspectDiskSpace = 17, AcquireDirectoryLock = 18, RemoveOwnedFile = 19, InspectResearchDirectory = 20, CreateResearchDirectory = 21, SyncResearchParent = 22, InspectDescriptorLimit = 23, InspectDescriptors = 24, CreateNodeDirectory = 25, ResolveNodeDirectory = 26, InspectNodeDirectory = 27, SecureNodeDirectory = 28, OpenLog = 29, InspectLog = 30, TruncateLog = 31, CopyLog = 32, WriteLog = 33, SeekLog = 34, ReadLog = 35, SyncLog = 36, CreateRuntimeFile = 37, WriteRuntimeFile = 38, SyncRuntimeFile = 39, RemoveIdentityStage = 40, PublishIdentityReceipt = 41, SyncIdentityDirectory = 42 }

    pub enum ProofCommandFault in 81 { RecordBytes = 1, JsonIo = 2, JsonSyntax = 3, JsonData = 4, JsonEof = 5 }

    /// Element storage classes reported by the model backend.
    pub enum TensorElementType in 80 {
        F64 = 1, F32 = 2, Flex32 = 3, F16 = 4, Bf16 = 5,
        I64 = 6, I32 = 7, I16 = 8, I8 = 9,
        U64 = 10, U32 = 11, U16 = 12, U8 = 13,
        BoolNative = 14, BoolU8 = 15, BoolU32 = 16, Quantized = 17,
    }

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
        DefinitionSnapshotCapacity = 110,
        DefinitionSelectionIndex = 111,
        DefinitionAvailability = 112,
        DefinitionTraceSnapshotMissing = 113,
        ConflictingProviders = 114, InvalidRoleLimits = 115, DeveloperWorkloadUnavailable = 116,
        PeerCursorBeyondGraph = 117, CommandQueueFull = 118, ServiceStopped = 119,
        ProgramGroupMissing = 120, CandidatePrefixMismatch = 121,
        CandidateCheckpointInsideGroup = 122, CandidateInputMismatch = 123,
        CandidateUnitOverflow = 124, CandidateStreamMismatch = 125,
        CandidateSealMissing = 126, CandidateCheckedMissing = 127,
        RecoveryFifoIdentity = 128, RecoveryRecordMissing = 129,
        RecoveryRecordIdentity = 130, RecoveryBytesOverflow = 131,
        EvidenceMissing = 132, EvidenceRandomState = 133, EvidenceObservationSequence = 134,
        EvidenceIdentity = 135, EvidenceHelperCapacity = 136, EvidenceHelperSource = 137, EvidenceOutcome = 138, EvidenceInitialization = 139, EvidenceDrawOverflow = 140, EvidenceObservationOverflow = 141, EvidenceCompletedReceipt = 142, EvidenceAttemptOverflow = 143, EvidenceWorkOverflow = 144, EvidenceTimeOverflow = 145, EvidencePlanBinding = 146, EvidencePlanCycle = 147, EvidencePreparedJob = 148, EvidenceCandidateRequired = 149, EvidenceProofSourceMissing = 150, EvidenceProofIdentity = 151, EvidenceSupportReceipt = 152, EvidenceSupportOverflow = 153,
        ExperienceJobBinding = 154, ExperienceNativeBinding = 155, ExperienceTerminalState = 156, ExperienceOutcome = 157, ExperienceStoredBinding = 158,
        ExperienceTerminalCandidate = 159, ExperienceNativeContext = 160, ExperienceResultMissing = 161, ExperienceCheckpointMissing = 162, ExperienceExecutionMismatch = 163, ExperiencePeerSyntax = 164, ExperiencePeerEncoding = 165, ExperienceReceiptIdentity = 166, ExperienceTraceMismatch = 167, ExperienceLineage = 168, ExperienceObservationBinding = 169,
        FrontierFormulaCapacity = 170, FrontierFormulaEncoding = 171, FrontierObservationCapacity = 172, FrontierTargetBinding = 173, FrontierStateCapacity = 174, FrontierAssumptionBinding = 175, FrontierSerialization = 176,
        TraceFormulaEncoding = 177, TraceCapacity = 178, TraceRootMissing = 179, TraceTargetMismatch = 180, TraceTheoremCapacity = 181, TraceExpansionOrder = 182, TraceParentOrder = 183, TraceBranchAncestry = 184, TraceBranchNotOffered = 185, TraceStateBinding = 186, TraceRankingShape = 187, TraceRankingOrder = 188, TraceBranchCount = 189, TraceRepairAttemptMissing = 190, TraceRepairDecision = 191, TraceRepairRootMissing = 192, TraceRepairSnapshotMissing = 193, TraceRepairAlternative = 194, TraceRepairConclusion = 195, TraceQuestionBinding = 196, TraceSnapshotMissing = 197, TraceTheoremIdentity = 198, TraceClosedDepth = 199, TraceMultipleTerminals = 200, TraceSkippedAttempt = 201, TraceSerialization = 202, SearchFreshVariableExhausted = 203,
        SearchTheoremIndex = 204, SearchDoubleAction = 205, SearchNegatedImplication = 206, SearchModusPonens = 207, SearchPremise = 208, SearchBranchAction = 209, SearchUniversalAction = 210, SearchInstantiationShape = 211, SearchInstantiationPremise = 212, SearchWitnessFreshness = 213, SearchWitnessNegation = 214, SearchWitnessUniversal = 215, SearchEqualityAction = 216,
        ReplayDepth = 217, ReplayState = 218, ReplayPositiveIndex = 219, ReplayNegativeIndex = 220, ReplayClosure = 221, ReplayNestedAxiom = 222, ReplayAction = 223, ReplayArity = 224, ReplayTheoremIndex = 225, ReplayWitness = 226, ReplayWitnessBody = 227, ReplayWitnessDischarge = 228, ReplayEquality = 229, ReplayBranch = 230, ReplayScopedTarget = 231, ReplayTheoremTarget = 232, ReplayDefinitionAvailability = 233, ReplayDefinitionIndex = 234, ReplayDefinitionUnused = 235, ReplayOwnedSnapshot = 236, ReplayAxiomIndex = 237, ReplayAxiomTarget = 238, ReplayAssumptionWrapper = 239, ReplayCompiledTarget = 240,
        ScopeTraceTarget = 241, ScopeTraceCapacity = 242, ScopeReplayOperand = 243, ScopeConclusion = 244, ScopeCitationMissing = 245, ScopeCitationFormulaMissing = 246, ScopeProgramTarget = 247, ScopeProgramOperands = 248, ScopeOperandOrder = 249, ScopeResultOrder = 250,
        PeerReplayCapacity = 251, PeerClosureCapacity = 252, PeerConclusion = 253, PeerWorkCapacity = 254, PeerReconstructionIdentity = 255, PeerStepCapacity = 256, PeerImplicationIndex = 257, PeerImplicationShape = 258, PeerPremiseIndex = 259, PeerPremiseMismatch = 260, PeerGraphOverflow = 261, PeerGraphCapacity = 262, PeerGeneralizationIndex = 263, PeerCitationMissing = 264, PeerCitationFormulaMissing = 265,
        PeerProgramArtifact = 266, PeerProgramInference = 267, PeerProgramBinding = 268, PeerDagBinding = 269, PeerDagInference = 270, PeerArtifactIdentity = 271,
        EvidenceCheckerCapacity = 272, EvidenceCanonicalBinding = 273, EvidenceTargetBinding = 274,
        NativeDagTargetMismatch = 275, NativeTermTargetMismatch = 276, NativeCheckedTargetMismatch = 277, KnowledgeTraceMissing = 278,
        ProofApplicationShape = 279, ProofApplicationAntecedent = 280, ProofCombinatorShape = 281, ProofCombinatorAntecedent = 282, ProofGeneralizationCapture = 283, ProofUnboundVariable = 284, ProofLemmaTarget = 285, ProofSealedTarget = 286, ProofUndischargedAssumption = 287, ProofIndexWidth = 288,
        LogicOpenLemma = 289, LogicLemmaInstantiation = 290, LogicProjectionShape = 291, LogicProjectionResult = 292, LogicExistentialGoal = 293, LogicExistentialPremise = 294, LogicEigenvariableEscape = 295, LogicExistentialElimination = 296, LogicExistentialOpening = 297, LogicContradiction = 298, LogicDoubleNegation = 299, LogicNegatedImplication = 300, LogicFreshVariable = 301, LogicUniversalPremise = 302,
        ProofReferenceReplacement = 304, ProofRepresentationMismatch = 305, DefinitionBinderSpace = 306, DefinitionBinder = 307, DefinitionProposalBinder = 308, DefinitionProposalUniversal = 309, DefinitionScores = 310, DefinitionChoicesEmpty = 311, KernelUnsupported = 312,
        FragmentFormulaEncoding = 313, FragmentObservedJob = 314, FragmentCapacity = 315, FragmentVariableScope = 316, FragmentClosedTarget = 317, FragmentIdentity = 318, FragmentSourceLineage = 319, FragmentBranchSource = 320, FragmentChild = 321, FragmentTransition = 322, FragmentBranchBinding = 323, FragmentObservedParent = 324, FragmentObservedReceipt = 325, FragmentExecutionMissing = 326, FragmentClosedBranchMissing = 327, FragmentObservedSubtree = 328, FragmentRecordedScope = 329, FragmentNegatedGoal = 330, FragmentNegationBinding = 331, FragmentOpenScope = 332, DerivationDepth = 333, DerivationNestedEvidence = 334, DerivationAction = 335, DerivationArity = 336, DerivationCitationIndex = 337, DerivationSourceIdentity = 338,
        CompositionTraceCapacity = 339, CompositionInputBinding = 340,
        CompositionCheckedInputMissing = 341, CompositionReplayMismatch = 342,
        CompositionDeductionSourceMissing = 343, CompositionDeductionIdentity = 344,
        CandidateStatementWidth = 345, CandidateCertificateWidth = 346,
        CandidateCertificateIdentity = 347, CandidateScopeTarget = 348, CandidateDefinitionIndex = 349,
        PeerProgramFrameWidth = 350, PeerProgramFrameTruncated = 351, PeerProgramCommandCapacity = 352,
        PeerProgramWorkOverflow = 353, PeerProgramWorkCapacity = 354, PeerProgramContextCapacity = 355,
        PeerProgramDependencyTrailing = 356, PeerProgramStepOverflow = 357, PeerProgramStepCapacity = 358, PeerProgramObjectCapacity = 359,
        PeerProgramFrameOutputWidth = 360, PeerProgramPacketCapacity = 361, PeerProgramContextBytesOverflow = 362,
        PeerProgramContextBytesCapacity = 363, PeerPrerequisiteProofBinding = 364, PeerPrerequisiteStatement = 365,
        PeerPrerequisiteDefinitionBinding = 366, PeerPrerequisiteObligationMissing = 367, PeerPrerequisiteObligationBinding = 368, PeerProgramConclusionCapacity = 369, PeerProgramConclusionMismatch = 370, PeerPrerequisiteFormulaMissing = 371, GeneratedTraceMissing = 372,
        JobParentSnapshot = 373, JobHistoryRequestBinding = 374, JobHistoryRequestMissing = 375, JobReplaySnapshotBinding = 376, JobArtifactLifetimeCapacity = 377, JobArtifactReservation = 378, JobReplayReceiptBinding = 379, JobReplayPreparationMissing = 380, JobObservationWorkOverflow = 381, JobObservationBinding = 382, JobMetaPlanContext = 383, JobMetaPlanMissing = 384, JobMetaCost = 385, JobMetaUpdatePlanMissing = 386, JobMetaUpdateBinding = 387, JobMetaUpdateMissing = 388, JobCheckpointCapacity = 389, JobPromotionBinding = 390, JobTransferCoverage = 391, JobDevelopmentBinding = 392, JobCompositionBinding = 393, JobModelQualification = 394, JobSamplingContinuation = 395, JobQualificationSequence = 396, JobFinderBinding = 397, JobCheckpointUnit = 398, JobPrerequisiteRole = 399,
        LearningExampleOwner = 400, LearningExampleEligibility = 401, LearningReplayPointer = 402, LearningProgramProvenance = 403, LearningProofProvenance = 404, LearningProgramTarget = 405, LearningDefinitionUtility = 406, LearningStateCapacity = 407, LearningReplayStrategyCapacity = 408, LearningFeedbackModel = 409,
        LearningFixedSnapshotCapacity = 410, LearningMetaHeadroom = 411, LearningMetaBatchCapacity = 412, LearningLocalCountOverflow = 413, LearningPeerCountOverflow = 414, LearningSequenceOverflow = 415, LearningRevisionOverflow = 416,
        ProgressMetaJobBinding = 417, ProgressRepeatedMismatch = 418, ProgressContinuationMismatch = 419, ProgressMetaTrialBinding = 420, ProgressFirstUnit = 421, ProgressTransferLoss = 422,
        JournalConfiguration = 423, JournalSequence = 424, JournalUnitsOverflow = 425, JournalTimeOverflow = 426, JournalAllowance = 427, JournalTrainingRole = 428, JournalLearningEpoch = 429, JournalFrontierRole = 430, JournalResolvedFrontier = 431, JournalHistoryJob = 432, JournalMetaJob = 433, JournalProviderRole = 434, JournalProviderMissing = 435, JournalHorizonOverflow = 436, JournalRecordBinding = 437, JournalProgramCheckpoint = 438, JournalAccountMissing = 439, JournalAccountBinding = 440, JournalFinderCursor = 441, JournalAccountCorrupt = 442,
        RoleHistoryFormat = 443, OutputFrontierRole = 444, OutputFrontierResolved = 445, OutputTypeCapacity = 446,
        ReplaySnapshotMissing = 447, ReplaySnapshotBinding = 448, ReplayCoverageBinding = 449, ReplayTrainingSplit = 450, ReplayProgramBinding = 451, ReplayProofBinding = 452,
        CoverageFilterInvalid = 453, CoverageProgramIdentity = 454, CoverageProofIdentity = 455, CoverageDependencyOrder = 456, CoverageActionMissing = 457, CoverageGraphReference = 458,
        PoolHindsightSourceCapacity = 459, PoolMaskWorkOverflow = 460, PoolMaskWorkCapacity = 461, PoolHindsightWorkOverflow = 462, PoolHindsightWorkCapacity = 463, PoolObservationLineage = 464, PoolSequenceWorkOverflow = 465, PoolSequenceWorkCapacity = 466, PoolSequenceBinding = 467, PoolWitnessWorkOverflow = 468, PoolDerivedWorkOverflow = 469, PoolDerivedWorkCapacity = 470, PoolGraphWorkOverflow = 471, PoolGraphWorkCapacity = 472,
        PreservationRootBranch = 473, PreservationPredecessor = 474, PreservationBranchBinding = 475, PreservationActionLabel = 476, PoolPredictionInvalid = 477,
        ModelCheckpointBinding = 478, MetaCheckpointBinding = 479, MetaCheckpointShape = 480, MetaTransferIncomplete = 481, MetaPromotionBinding = 482, MetaTrialDimensions = 483, MetaMemoryCapacity = 484, MetaTrialDuplicate = 485, MetaSelectionValues = 486, MetaPlanObjective = 487, MetaMemoryPhase = 488, TransferCoverageInvalid = 489, TransferSequence = 490,
        AbilityProfileCapacity = 491, AbilityUtilityBinding = 492, AbilityCheckpointBinding = 493, FinderUtilityCapacity = 494, FinderUtilityIdentity = 495, FinderExampleEligibility = 496, FinderProofIdentity = 497, UtilityGradientInvalid = 498, UtilityReferenceCapacity = 499,
        MetaUpdateExperienceMissing = 500, MetaOptimizationNonFinite = 501, MetaOptimizerCounterOverflow = 502, MetaWeightWidth = 503, MetaOptimizerWidth = 504, MetaOptimizerCounter = 505, MetaWeightValue = 506, MetaOptimizerValue = 507, MetaSecondMoment = 508, MetaExperienceBinding = 509,
        ModelChunkMissing = 510, ModelChunkLength = 511, ModelDigestMismatch = 512, ModelReceiptMissing = 513,
        ReplaySourceJobMissing = 514, ReplaySourceSolutionMissing = 515, ReplaySampleMismatch = 516, ReplayResultMissing = 517, ReplayIdentityMismatch = 518, ReplayOwnReceiptMissing = 519, ReplayPeerReceiptMissing = 520, ReplayPeerReceiptMismatch = 521, ReplayProvenanceMismatch = 522, PeerQueueOrdinalMismatch = 523,
        PeerOrdinalZero = 524, PeerSyntax = 525, PeerEncoding = 526, PeerOwnerDisabled = 527, PeerArtifactMismatch = 528, PeerConversionJobMissing = 529, PeerConversionReceiptMissing = 530, PeerConversionOriginMismatch = 531, PeerLearningStateMissing = 532, TheoremCapacity = 533, TheoremNotClosed = 534,
        JournalNativeModelOwnerEncoding = 535, JournalMetaTrialExperienceDiffersFromItsOriginalOwnedJob = 536, JournalNativeLearningSingletonDiffers = 537, JournalNativeReplaySnapshotResultMissing = 538, JournalNativeReplaySnapshotSourceDiffers = 539, JournalNativeSnapshotLacksAdmittedLocalReceipt = 540, JournalNativeReplaySnapshotOriginRoleDiffers = 541, JournalNativeRecordModelOwnerIndexDiffers = 542, JournalNativeGlobalModelOwnerIndexDiffers = 543, JournalNativeModelOwnerIndexDiffers = 544, JournalNativeModelUseIndexMissing = 545, JournalNativeModelUseOwnerDiffers = 546, JournalNativeModelReclamationKeyDiffers = 547, JournalNativeModelChunkIdentityOrLengthDiffers = 548, JournalSeenProofSourceDiffers = 549, JournalNativeSampleProvenanceCountersDiffer = 550, JournalNativeSamplesLackLearningState = 551, JournalPeerPendingSourceDiffers = 552, JournalOwnLearningAdmissionReceiptDiffers = 553, JournalPeerAdmissionSourceDiffers = 554, JournalPeerAdmissionPendingIndexDiffers = 555, JournalFinishedPeerAdmissionRemainsQueued = 556, JournalPeerConversionJobSourceDiffers = 557, JournalPeerConversionProofReceiptDiffers = 558, JournalNativeSampleSourceRoleDiffers = 559, JournalNativeSampleSourceIdentityDiffers = 560, JournalNativeSampleOwnAdmissionAbsent = 561, JournalNativeSamplePeerConversionDiffers = 562, JournalNativeSourceJobMissing = 563, JournalNativeModelOwnerSyntax = 564, JournalMetaTrialSourceUpdateAbsent = 565, JournalNativeModelUseKey = 566, JournalNativeModelChunkKey = 567, JournalNativeModelChunkHasNoOwnerOrReclamationReceipt = 568, JournalPeerPendingReceiptMissing = 569, JournalNativeSamplePeerAdmissionAbsent = 570, JournalNativeModelOwnerIdentity = 571, JournalNativeModelChunkIndex = 572, JournalOwnLearningReceiptIdentity = 573, JournalPeerAdmissionSyntax = 574,
        ModelInitializationPoisoned = 575, ModelParameterCountMismatch = 576, ModelOptimizerRestorationMismatch = 577, ModelUpdatesOverflow = 578,
        BackendPackHeader = 579, BackendPackMagic = 580, BackendPackVersion = 581, BackendPackMetadataWrite = 582, BackendPackMetadataRead = 583, BackendPackIo = 584, BackendPackTensorMissing = 585, BackendPackTensorSize = 586, BackendPackValidation = 587, BackendPackExists = 588, BackendRecordIo = 589, BackendRecordValidation = 590,
        PreservationStepsMissing = 591, PreservationStepsInvalid = 592, PreservationStepsExceeded = 593, PreservationUnknownField = 594, PreservationParameterMismatch = 595, PreservationValueInvalid = 596, PreservationIncomplete = 597,
        TensorStorageAccess = 598, TensorInvalidRepresentation = 599, TensorDtypeMismatch = 600, TensorUnsupportedConversion = 601, TensorElementCountMismatch = 602, TensorByteLengthInvalid = 603, TrainingLossCount = 604, TrainingLossNonFinite = 605, TrainingPoolEmpty = 606,
        SequenceEmpty = 607, SequenceShape = 608, SequenceCapacity = 609, SequencePredecessor = 610, SequenceDepth = 611, SequenceSelectedAction = 612, SequenceMemoryMissing = 613, SequenceOutputMissing = 614, PreservationStepsOverflow = 615, PreservationIdentityMismatch = 616,
        ModelReclamationIdentity = 617, LearningReceiptMismatch = 618, LearningResultMissing = 619, LearningResultIncomplete = 620, LearningSourceRole = 621, LearningProgramIdentity = 622, LearningOwnerMissing = 623, TheoremIdentityMismatch = 624, AcknowledgementUnknown = 625, AcknowledgementNotTerminal = 626,
        JournalHoldAccountMissing = 627, JournalActiveBytesOverflow = 628, JobInputEncoding = 629, JobReservationOverflow = 630, JobResultReservationOverflow = 631, JobHorizonOverflow = 632, QueuedJobMissing = 633, CompletionJobMissing = 634,
        SlotLaneInvalid = 635, SlotParentMissing = 636, SlotIdentityMismatch = 637, SlotWorkersActive = 638, IndexedRequestMissing = 639, IndexedRequestMismatch = 640,
        RecoveryProgramKey = 641, RecoveryProgramJobSyntax = 642, RecoveryProgramUnitSyntax = 643, RecoveryProgramKeyCanonical = 644, RecoveryProgramJobMissing = 645, RecoveryProgramReservation = 646, RecoveryHeaderInvalid = 647, RecoveryResidentIndex = 648, RecoverySlotAllocation = 649, RecoveryLearningMissing = 650, RecoveryRecordRowIdentity = 651, RecoveryRequestCountOverflow = 652, RecoveryRequestBinding = 653, RecoveryResidentBytesOverflow = 654, RecoveryHistoryCardinality = 655, RecoveryRequestCardinality = 656, RecoveryResidentMissing = 657, RecoveryResidentDisappeared = 658, RecoveryRetiredCountOverflow = 659, RecoveryArchiveUnitsOverflow = 660, RecoveryArchiveTimeOverflow = 661, RecoveryHeldJobMissing = 662, RecoveryHeldAccountMismatch = 663, RecoveryArchiveAllowance = 664,
        TheoremOrdinalZero = 665, DefinitionOrdinalZero = 666, PendingLearningReceiptMismatch = 667, DuplicateHistoryRead = 668, DuplicateModelIo = 669, DuplicateLearningCheckpoint = 670, ResidentJobMissing = 671, JournalActiveCapacity = 672, JournalReservedCapacity = 673, DiskReservationWidth = 674,
        ProviderInvocationRequired = 675, ProviderPipeCapacity = 676, ProviderStartDecoding = 677, ProviderStartInvalid = 678, ProviderWorkerInputMissing = 679, ProviderWorkerOutputMissing = 680, ProviderStopped = 681, DescendantSignalEnded = 682, DescendantOwnerPanic = 683, ProviderRoleMismatch = 684, ProviderUnknown = 685, MockProgramUnit = 686,
        ProviderPidOverflow = 687, ProviderTermSignal = 688, ProviderKillSignal = 689, ProviderChildKill = 690, ProviderWaitFailed = 691, ProviderReapDeadline = 692, ProviderGroupProbe = 693, ProviderGroupUnconfirmed = 694,
        TheoremDuplicate = 695, RequiredTheoremCapacity = 696, TheoremStepOverflow = 697, TheoremAvailabilityMismatch = 698, ConstructionAvailabilityMismatch = 699, DefinitionSnapshotMismatch = 700,
        ConstructionScoreCount = 701, ConstructionScoreNonFinite = 702, ConstructionSourceNotClosed = 703, ConstructionSelectionIndex = 704, ConstructionMeaningMismatch = 705, ConstructionRootMissing = 706, ConstructionHelperForward = 707, ConstructionHelperWidth = 708, ConstructionRecipeEmpty = 709, ConstructionRecipeRootMismatch = 710,
        RepairDeadline = 711, RepairWorkAllowance = 712, RepairProtectedProof = 713, RepairHelperConclusion = 714, RepairProtectedHelper = 715, RepairRootConclusion = 716, RepairClosureCapacity = 717, PartitionFreshVariable = 718, PartitionBinderMissing = 719, PartitionReferenceMismatch = 720, PartitionConclusionMissing = 721, PartitionVariableInventory = 722, PartitionOriginMissing = 723, PartitionTargetMismatch = 724, PartitionArtifactCapacity = 725, PartitionReplayMismatch = 726, PartitionCutMissing = 727,
        FinderDescriptorShape = 728, FinderDescriptorBinding = 729, FinderPredictorWidth = 730, FinderUtilityWidth = 731, FinderPredictorWeight = 732, FinderUtilityWeight = 733, FinderObservationCounts = 734, FinderUtilityLabel = 735, FinderUtilityOverflow = 736, FinderReplayUtility = 737, FinderRehearsalOverflow = 738, FinderUpdateOverflow = 739, FinderSuccessOverflow = 740, FinderAttemptOverflow = 741, FinderSupportOverflow = 742, FinderRecipeInvalid = 743, FinderCurriculumCapacity = 744, FinderCurriculumCounts = 745, FinderRehearsalInvalid = 746, FinderCursorOverflow = 747, PeerSealMissing = 748, PeerOperandWidth = 749, PeerOperandOrder = 750, MeasurementScopeMismatch = 751, MeasurementCounterOverflow = 752,
        InternalCutTargetMismatch = 753, DefinitionAuthorshipIdentity = 754, FinderDecisionInvalid = 755, ResearchValueInvalid = 756,
    }

}

/// A bounded LZ4 decoding failure shared by all compressed input paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompressionFailure {
    OutputTooSmall { expected: usize, actual: usize },
    SizeMismatch { expected: usize, actual: usize },
    LiteralOutOfBounds,
    ExpectedAnotherByte,
    OffsetZero,
    OffsetOutOfBounds,
    Unknown,
}

impl From<lz4_flex::block::DecompressError> for CompressionFailure {
    fn from(error: lz4_flex::block::DecompressError) -> Self {
        use lz4_flex::block::DecompressError;
        match error {
            DecompressError::OutputTooSmall { expected, actual } => {
                Self::OutputTooSmall { expected, actual }
            }
            DecompressError::LiteralOutOfBounds => Self::LiteralOutOfBounds,
            DecompressError::ExpectedAnotherByte => Self::ExpectedAnotherByte,
            DecompressError::OffsetZero => Self::OffsetZero,
            DecompressError::OffsetOutOfBounds => Self::OffsetOutOfBounds,
            _ => Self::Unknown,
        }
    }
}

impl serde::Serialize for CompressionFailure {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut value = serializer.serialize_struct(
            "CompressionFailure",
            if matches!(
                self,
                Self::OutputTooSmall { .. } | Self::SizeMismatch { .. }
            ) {
                3
            } else {
                1
            },
        )?;
        let reason: u8 = match self {
            Self::OutputTooSmall { .. } => 1,
            Self::LiteralOutOfBounds => 2,
            Self::ExpectedAnotherByte => 3,
            Self::OffsetZero => 4,
            Self::OffsetOutOfBounds => 5,
            Self::Unknown => 6,
            Self::SizeMismatch { .. } => 7,
        };
        value.serialize_field("reason", &reason)?;
        if let Self::OutputTooSmall { expected, actual } | Self::SizeMismatch { expected, actual } =
            self
        {
            value.serialize_field("expected", expected)?;
            value.serialize_field("actual", actual)?;
        }
        value.end()
    }
}

impl std::fmt::Display for CompressionFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "compression failure {self:?}")
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
        ErrorKind::AlreadyExists => Code::AlreadyExists,
        ErrorKind::InvalidInput => Code::InvalidInput,
        ErrorKind::InvalidData => Code::InvalidData,
        ErrorKind::AddrInUse => Code::AddrInUse,
        ErrorKind::AddrNotAvailable => Code::AddrNotAvailable,
        ErrorKind::WriteZero => Code::WriteZero,
        ErrorKind::Unsupported => Code::Unsupported,
        ErrorKind::NotADirectory => Code::NotADirectory,
        ErrorKind::IsADirectory => Code::IsADirectory,
        ErrorKind::DirectoryNotEmpty => Code::DirectoryNotEmpty,
        ErrorKind::ReadOnlyFilesystem => Code::ReadOnlyFilesystem,
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
            Self::IntakeDescriptionCapacity => "description queue capacity",
            Self::IntakeProgramDescriptionCapacity => "program description queue capacity",
            Self::NetworkDiscoveryCapacity => "network discovery configuration capacity",
            Self::ProducerQueue => "producer queue capacity",
            Self::PeerCertificateCapacity => "peer compressed admission capacity",
            Self::PeerProgramCapacity => "peer program replay capacity",
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
