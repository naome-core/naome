"""Small authorized fixtures verify loader control flow, never model quality."""
import contextlib
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location("qwen", Path(__file__).with_name("qwen.py"))
QWEN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(QWEN)


class TensorFixture:
    def __init__(self, dtype, pointer, shape=(2, 2)):
        self.dtype, self.pointer, self.shape = dtype, pointer, shape
        self.device = SimpleNamespace(type="cpu")

    @property
    def is_meta(self):
        return self.device.type == "meta"

    def stride(self):
        return (self.shape[1], 1) if len(self.shape) == 2 else (1,)

    def storage_offset(self):
        return 0

    def untyped_storage(self):
        return SimpleNamespace(data_ptr=lambda: self.pointer)

    def numel(self):
        value = 1
        for dimension in self.shape:
            value *= dimension
        return value

    def element_size(self):
        return {"bfloat16": 2, "float32": 4, "int64": 8}[self.dtype]


class Qwen3ForCausalLM:
    # Deliberate fixture identity for the control's mocked AutoModel factory.
    __module__ = "transformers.models.qwen3.modeling_qwen3"

    def __init__(self, tied=False, corruption=None):
        self.first = TensorFixture("bfloat16", 100)
        self.second = self.first if tied else TensorFixture("bfloat16", 200)
        self.buffers = {"frequency": TensorFixture("float32", 300, (2,)),
                        "indices": TensorFixture("int64", 400, (1,))}
        self.config = SimpleNamespace(tie_word_embeddings=tied)
        self.corruption, self.transfers, self.forwards = corruption, [], []
        self.events = []

    def named_parameters(self, remove_duplicate=True):
        values = [("embedding.weight", self.first), ("lm_head.weight", self.second)]
        return values[:1] if remove_duplicate and self.first is self.second else values

    def parameters(self):
        return [value for _, value in self.named_parameters()]

    def named_buffers(self, remove_duplicate=True):
        return list(self.buffers.items())

    def get_input_embeddings(self):
        return SimpleNamespace(weight=self.first)

    def get_output_embeddings(self):
        return SimpleNamespace(weight=self.second)

    def eval(self):
        self.events.append("eval")
        return self

    def requires_grad_(self, value):
        assert value is False
        self.events.append("no_grad")
        return self

    def to(self, **kwargs):
        self.transfers.append(kwargs)
        assert kwargs == {"device": "mps"}, "dtype argument would cast original buffers"
        if self.corruption == "transfer_failure":
            raise RuntimeError("injected transfer failure")
        if self.corruption == "new_instance":
            return Qwen3ForCausalLM()
        for value in self.parameters() + list(self.buffers.values()):
            value.device.type = "mps"
        if self.corruption in ("cpu_parameter", "meta_parameter"):
            self.first.device.type = "cpu" if self.corruption == "cpu_parameter" else "meta"
        if self.corruption == "cpu_buffer":
            self.buffers["frequency"].device.type = "cpu"
        if self.corruption == "parameter_dtype":
            self.first.dtype = "float32"
        if self.corruption == "buffer_dtype":
            self.buffers["frequency"].dtype = "bfloat16"
        if self.corruption == "integer_buffer_dtype":
            self.buffers["indices"].dtype = "float32"
        if self.corruption == "buffer_shape":
            self.buffers["frequency"].shape = (1, 2)
        if self.corruption == "broken_tie":
            self.second = TensorFixture("bfloat16", 201)
            self.second.device.type = "mps"
        return self

    def __call__(self, **kwargs):
        assert self.transfers, "no CPU forward before transfer"
        assert all(value.device.type == "mps" for value in self.parameters() + list(self.buffers.values()))
        assert kwargs["input_ids"].device.type == "mps"
        self.forwards.append(kwargs)


class BatchFixture(dict):
    def __init__(self):
        super().__init__(input_ids=TensorFixture("int64", 500, (1,)))

    def to(self, device):
        assert device == "mps"
        self["input_ids"].device.type = device
        return self


class LoaderControls(unittest.TestCase):
    def constructor(self, model, loading=None, available=True):
        temporary = tempfile.TemporaryDirectory(prefix="qwen-loader-fixture-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        template = "fixed template fixture"
        payload = json.dumps({"chat_template": template}).encode()
        (root / "tokenizer_config.json").write_bytes(payload)
        manifest = {"schema": 1, "repository": QWEN.MODEL_REPOSITORY, "revision": QWEN.MODEL_REVISION,
                    "files": [{"name": "tokenizer_config.json", "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}]}
        authorized = hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        auto_model = SimpleNamespace(from_pretrained=Mock(return_value=(model, loading or {})))
        tokenizer = SimpleNamespace(chat_template=template, encode=lambda text, **_: [QWEN.LABELS[text]],
                                    decode=lambda ids: next(label for label, value in QWEN.LABELS.items() if ids == [value]))

        class TokenizerFixture:
            chat_template = tokenizer.chat_template
            encode, decode = staticmethod(tokenizer.encode), staticmethod(tokenizer.decode)

            def __call__(self, *_args, **_kwargs):
                return BatchFixture()

        torch = SimpleNamespace(bfloat16="bfloat16", set_num_threads=Mock(), inference_mode=contextlib.nullcontext,
                                backends=SimpleNamespace(mps=SimpleNamespace(is_available=lambda: available)),
                                mps=SimpleNamespace(set_per_process_memory_fraction=Mock(), synchronize=Mock()))
        transformers = SimpleNamespace(AutoModelForCausalLM=auto_model,
                                       AutoTokenizer=SimpleNamespace(from_pretrained=Mock(return_value=TokenizerFixture())))
        observations = []
        with patch.dict(sys.modules, {"torch": torch, "transformers": transformers}), \
                patch.object(QWEN.importlib.metadata, "version", side_effect=lambda name: QWEN.BACKEND_VERSIONS[name]), \
                patch.object(QWEN, "MODEL_MANIFEST_HASH", authorized), \
                patch.object(QWEN, "verified_parameter_bytes", return_value=sum(p.numel() * p.element_size() for p in model.parameters())):
            result = QWEN.ResidentModel(root, "mps", manifest, "cpu-staged-mps-v1",
                                       lambda stage, values: observations.append((stage, values)))
        return result, auto_model, torch, observations

    def test_same_instance_cpu_staging_has_only_mps_warmup_and_preserves_buffers(self):
        model = Qwen3ForCausalLM()
        resident, factory, torch, stages = self.constructor(model)
        self.assertIs(resident.model, model)
        self.assertEqual(factory.from_pretrained.call_count, 1)
        args = factory.from_pretrained.call_args.kwargs
        self.assertEqual(args["device_map"], "cpu")
        self.assertEqual(args["dtype"], "bfloat16")
        self.assertEqual(args["attn_implementation"], "sdpa")
        self.assertTrue(args["local_files_only"] and args["use_safetensors"] and args["output_loading_info"])
        self.assertFalse(args["trust_remote_code"])
        self.assertEqual(model.transfers, [{"device": "mps"}])
        self.assertEqual(len(model.forwards), 1)
        self.assertEqual(model.buffers["frequency"].dtype, "float32")
        self.assertEqual(model.buffers["indices"].dtype, "int64")
        self.assertEqual([stage for stage, _ in stages], ["verification", "backend", "cpu_load", "cpu_loaded", "mps_transfer", "mps_loaded", "warmup", "warmup_complete"])
        self.assertEqual(stages[3][1]["inventory"], stages[5][1]["inventory"])
        self.assertEqual(resident.inventory_hash, QWEN.inventory_hash(stages[3][1]["inventory"]))
        torch.mps.set_per_process_memory_fraction.assert_called_once_with(.80)

    def test_original_tied_embedding_storage_preserved(self):
        resident, _, _, _ = self.constructor(Qwen3ForCausalLM(tied=True))
        self.assertTrue(resident.tensor_inventory["embedding_tied"])
        self.assertEqual(resident.tensor_inventory["shared_views"], [["parameter:embedding.weight", "parameter:lm_head.weight"]])

    def test_corrupt_transfer_cannot_warm_or_become_ready(self):
        for case in ["transfer_failure", "new_instance", "cpu_parameter", "meta_parameter", "cpu_buffer",
                     "parameter_dtype", "buffer_dtype", "integer_buffer_dtype", "buffer_shape", "broken_tie"]:
            model = Qwen3ForCausalLM(tied=case == "broken_tie", corruption=case)
            with self.subTest(case=case), self.assertRaises((QWEN.Rejected, RuntimeError)):
                self.constructor(model)
            self.assertEqual(model.forwards, [])

    def test_incomplete_weight_loading_info_stops_before_transfer(self):
        for field in ["missing_keys", "unexpected_keys", "mismatched_keys", "error_msgs"]:
            model = Qwen3ForCausalLM()
            with self.subTest(field=field), self.assertRaisesRegex(QWEN.Rejected, "incomplete_pretrained_weights"):
                self.constructor(model, {field: ["injected incomplete weight"]})
            self.assertEqual(model.transfers, [])
            self.assertEqual(model.forwards, [])

    def test_unavailable_mps_has_no_cpu_inference_fallback(self):
        model = Qwen3ForCausalLM()
        with self.assertRaisesRegex(QWEN.Rejected, "device_unavailable"):
            self.constructor(model, available=False)
        self.assertEqual(model.transfers, [])
        self.assertEqual(model.forwards, [])

    def test_wrong_model_class_stops_before_transfer(self):
        class WrongClass(Qwen3ForCausalLM):
            pass
        model = WrongClass()
        with self.assertRaisesRegex(QWEN.Rejected, "model_class"):
            self.constructor(model)
        self.assertEqual(model.transfers, [])
        self.assertEqual(model.forwards, [])

    def test_real_pinned_metadata_binds_tensor_bytes_not_shard_file_sizes(self):
        # These are exact consumed fixed metadata inputs, not substituted toy
        # model totals. No Torch, weight payload or model allocation is used.
        fixture = Path(__file__).with_name("fixtures")
        expected = QWEN.verified_parameter_bytes(fixture)
        self.assertEqual(expected, 8044936192)
        self.assertEqual(expected // 2, 4022468096)
        manifest = json.loads(Path(__file__).with_name("model.lock.json").read_bytes())
        shard_files = sum(entry["size"] for entry in manifest["files"] if entry["name"].endswith(".safetensors"))
        self.assertEqual(shard_files, 8044982000)
        self.assertEqual(shard_files - expected, 45808)
        with patch.object(QWEN, "MODEL_PARAMETER_BYTES", shard_files):
            with self.assertRaisesRegex(QWEN.Rejected, "parameter_tensor_byte_binding"):
                QWEN.verified_parameter_bytes(fixture)
        for name, (size, digest) in QWEN.MODEL_METADATA_FILES.items():
            raw = (fixture / name).read_bytes()
            self.assertEqual(len(raw), size)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)
            self.assertEqual(next(entry["sha256"] for entry in manifest["files"] if entry["name"] == name), digest)

    def test_changed_metadata_rejected_before_model_factory(self):
        fixture = Path(__file__).with_name("fixtures")
        with tempfile.TemporaryDirectory(prefix="qwen-metadata-control-") as directory:
            target = Path(directory)
            for name in QWEN.MODEL_METADATA_FILES:
                (target / name).write_bytes((fixture / name).read_bytes())
            for name in QWEN.MODEL_METADATA_FILES:
                original = (target / name).read_bytes()
                (target / name).write_bytes(original + b" ")
                factory = SimpleNamespace(from_pretrained=Mock())
                with self.subTest(name=name), self.assertRaisesRegex(QWEN.Rejected, "parameter_metadata_binding"):
                    QWEN.load_pretrained(target, "mps", SimpleNamespace(), factory, "cpu-staged-mps-v1", lambda *_: None)
                factory.from_pretrained.assert_not_called()
                (target / name).write_bytes(original)


if __name__ == "__main__":
    unittest.main()
