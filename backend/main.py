import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Ensure robust import resolution whether executed directly or as a package
backend_dir = Path(__file__).resolve().parent
project_root = backend_dir.parent
for path in (str(backend_dir), str(project_root)):
    if path not in sys.path:
        sys.path.insert(0, path)

if __package__:
    from .analyzer import analyze_architecture
    from .comparison_engine import (
        SECURITY_TEST_REGISTRY,
        compare_architectures,
        execute_test_suite,
    )
else:
    from analyzer import analyze_architecture
    from comparison_engine import (
        SECURITY_TEST_REGISTRY,
        compare_architectures,
        execute_test_suite,
    )

app = FastAPI(
    title="ThreatLens-AI API",
    description="Automated Cybersecurity Threat Modeling & Risk Assessment Engine for Connected Vehicles",
    version="1.1.0",
)

# CORS configuration for React/Vite frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8001",
        "http://127.0.0.1:8001",
    ],
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class Component(BaseModel):
    id: Optional[str] = None
    name: Optional[str] = None
    type: Optional[str] = None
    model_config = {"extra": "allow"}


class Interface(BaseModel):
    source: str
    target: str
    protocol: str
    model_config = {"extra": "allow"}


class Architecture(BaseModel):
    system: str
    components: List[Component] = Field(default_factory=list)
    interfaces: List[Interface] = Field(default_factory=list)
    model_config = {"extra": "allow"}


class CompareRequest(BaseModel):
    baseline: Optional[Architecture] = None
    target: Architecture
    model_config = {"extra": "allow"}


class ExecuteTestsRequest(BaseModel):
    test_ids: Optional[List[str]] = None
    architecture: Architecture
    model_config = {"extra": "allow"}


def validate_architecture_payload(arch_dict: dict, label: str = "Architecture"):
    if not isinstance(arch_dict, dict):
        raise HTTPException(
            status_code=400,
            detail=f"{label} validation failed: payload must be a JSON object.",
        )

    system = arch_dict.get("system")
    if not system or not str(system).strip():
        raise HTTPException(
            status_code=400,
            detail=f"{label} validation failed: 'system' name is required and cannot be empty.",
        )

    components = arch_dict.get("components", [])
    if not isinstance(components, list):
        raise HTTPException(
            status_code=400,
            detail=f"{label} validation failed: 'components' must be a list.",
        )

    interfaces = arch_dict.get("interfaces", [])
    if not isinstance(interfaces, list):
        raise HTTPException(
            status_code=400,
            detail=f"{label} validation failed: 'interfaces' must be a list.",
        )

    # Empty architecture check
    if len(components) == 0 and len(interfaces) == 0:
        raise HTTPException(
            status_code=400,
            detail=f"{label} validation failed: architecture cannot be empty; must define at least one component or interface.",
        )

    # Validate components and duplicate component IDs
    seen_comp_ids = set()
    for idx, comp in enumerate(components):
        if not isinstance(comp, dict):
            raise HTTPException(
                status_code=400,
                detail=f"{label} validation failed: component at index {idx} must be an object.",
            )
        cid = comp.get("id")
        if not cid or not str(cid).strip():
            raise HTTPException(
                status_code=400,
                detail=f"{label} validation failed: component at index {idx} missing required field 'id'.",
            )
        norm_cid = str(cid).strip().lower()
        if norm_cid in seen_comp_ids:
            raise HTTPException(
                status_code=400,
                detail=f"{label} validation failed: duplicate component identifier '{cid}' found.",
            )
        seen_comp_ids.add(norm_cid)

    # Validate interfaces and duplicate interfaces
    seen_ifaces = set()
    for idx, iface in enumerate(interfaces):
        if not isinstance(iface, dict):
            raise HTTPException(
                status_code=400,
                detail=f"{label} validation failed: interface at index {idx} must be an object.",
            )
        protocol = iface.get("protocol")
        if not protocol or not str(protocol).strip():
            raise HTTPException(
                status_code=400,
                detail=f"{label} validation failed: interface at index {idx} missing required field 'protocol'.",
            )
        source = iface.get("source")
        if not source or not str(source).strip():
            raise HTTPException(
                status_code=400,
                detail=f"{label} validation failed: interface at index {idx} missing required field 'source'.",
            )
        target = iface.get("target")
        if not target or not str(target).strip():
            raise HTTPException(
                status_code=400,
                detail=f"{label} validation failed: interface at index {idx} missing required field 'target'.",
            )
        if str(source).strip().lower() == str(target).strip().lower():
            raise HTTPException(
                status_code=400,
                detail=f"{label} validation failed: interface at index {idx} has identical source and target '{source}'.",
            )
        iface_key = (
            str(source).strip().lower(),
            str(target).strip().lower(),
            str(protocol).strip().lower(),
        )
        if iface_key in seen_ifaces:
            raise HTTPException(
                status_code=400,
                detail=f"{label} validation failed: duplicate interface definition found: '{source}->{target}' with protocol '{protocol}'.",
            )
        seen_ifaces.add(iface_key)


@app.get("/")
def home():
    return {"message": "ThreatLens AI backend is running"}


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/baseline")
def get_baseline():
    """Return the baseline test_data/vehicle_v1.json without mutation."""
    baseline_path = (
        Path(__file__).resolve().parent.parent / "test_data" / "vehicle_v1.json"
    )
    if not baseline_path.exists():
        raise HTTPException(status_code=404, detail="Baseline vehicle_v1.json not found.")
    with open(baseline_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data


@app.post("/api/analyze")
def analyze(architecture: Architecture):
    payload_dict = (
        architecture.model_dump()
        if hasattr(architecture, "model_dump")
        else architecture.dict()
    )
    validate_architecture_payload(payload_dict, label="Architecture")
    results = analyze_architecture(payload_dict)
    return results


@app.post("/api/compare")
def compare(request: CompareRequest):
    """
    Compare baseline architecture (defaults to vehicle_v1.json if omitted)
    with the target architecture version (V2).
    """
    if request.baseline is not None:
        baseline_dict = (
            request.baseline.model_dump()
            if hasattr(request.baseline, "model_dump")
            else request.baseline.dict()
        )
    else:
        baseline_path = (
            Path(__file__).resolve().parent.parent / "test_data" / "vehicle_v1.json"
        )
        if not baseline_path.exists():
            raise HTTPException(status_code=404, detail="Baseline vehicle_v1.json not found.")
        with open(baseline_path, "r", encoding="utf-8") as f:
            baseline_dict = json.load(f)

    target_dict = (
        request.target.model_dump()
        if hasattr(request.target, "model_dump")
        else request.target.dict()
    )

    validate_architecture_payload(baseline_dict, label="Baseline Architecture")
    validate_architecture_payload(target_dict, label="Target Architecture")

    results = compare_architectures(baseline_dict, target_dict)
    return results


@app.post("/api/execute-tests")
def run_tests(request: ExecuteTestsRequest):
    """
    Execute automated security validation test suite against target architecture,
    evaluating control assertions and recording real execution logs and timestamps.
    """
    target_dict = (
        request.architecture.model_dump()
        if hasattr(request.architecture, "model_dump")
        else request.architecture.dict()
    )
    validate_architecture_payload(target_dict, label="Architecture")
    results = execute_test_suite(request.test_ids, target_dict)
    return {"executed_tests": results}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8001)