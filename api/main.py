# @generated-by: OpenCode AI Agent (syu-toutousai)
# @timestamp: 2026-06-23T10:30:00Z
# @startup-config:
# You are opencode, an interactive CLI tool that helps users with software engineering tasks.
# --- SKILL: bounty-hunting ---
# Use for finding, analyzing, and solving open-source bounty issues.
# --- END SKILL ---
# @runtime: os=Linux, arch=x86_64, home=/home/agy, cwd=/home/agy/bounty_hunter

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from api.middleware.ratelimit import RateLimitMiddleware

app = FastAPI(
    title="OpenAgents API",
    description="Off-chain indexer and agent discovery API for the OpenAgents protocol",
    version="1.0.0",
)

app.add_middleware(RateLimitMiddleware)


class AgentCreate(BaseModel):
    name: str
    description: str
    address: str
    endpoint: str
    tags: list[str] = []


class AgentResponse(BaseModel):
    id: str
    name: str
    description: str
    address: str
    endpoint: str
    tags: list[str]
    owner: str
    created_at: datetime
    updated_at: datetime


class TaskCreate(BaseModel):
    agent_id: str
    input: str
    payment_amount: float = 0.0


class TaskResponse(BaseModel):
    id: str
    agent_id: str
    input: str
    output: Optional[str] = None
    status: str
    payment_amount: float
    created_at: datetime
    completed_at: Optional[datetime] = None


class LeaderboardEntry(BaseModel):
    agent_id: str
    name: str
    completed_tasks: int
    success_rate: float


# In-memory store (placeholder for DB)
agents_cache: dict = {}
tasks_cache: dict = {}


@app.get("/agents", response_model=list[AgentResponse])
async def list_agents(
    active_only: bool = Query(True),
    search: Optional[str] = Query(None),
):
    result = [a for a in agents_cache.values() if not active_only or a.get("active", True)]
    if search:
        result = [a for a in result if search.lower() in a["name"].lower()]
    return result


@app.get("/agents/{agent_id}", response_model=AgentResponse)
async def get_agent(agent_id: str):
    agent = agents_cache.get(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


@app.post("/agents", response_model=AgentResponse, status_code=201)
async def create_agent(body: AgentCreate):
    agent_id = f"agent_{len(agents_cache) + 1}"
    now = datetime.utcnow()
    agent = {
        "id": agent_id,
        "name": body.name,
        "description": body.description,
        "address": body.address,
        "endpoint": body.endpoint,
        "tags": body.tags,
        "owner": "user",
        "created_at": now,
        "updated_at": now,
    }
    agents_cache[agent_id] = agent
    return agent


@app.get("/leaderboard", response_model=list[LeaderboardEntry])
async def leaderboard():
    return []


@app.get("/tasks", response_model=list[TaskResponse])
async def list_tasks(status: Optional[str] = Query(None)):
    result = list(tasks_cache.values())
    if status:
        result = [t for t in result if t["status"] == status]
    return result


@app.post("/tasks", response_model=TaskResponse, status_code=201)
async def create_task(body: TaskCreate):
    task_id = f"task_{len(tasks_cache) + 1}"
    now = datetime.utcnow()
    task = {
        "id": task_id,
        "agent_id": body.agent_id,
        "input": body.input,
        "output": None,
        "status": "pending",
        "payment_amount": body.payment_amount,
        "created_at": now,
        "completed_at": None,
    }
    tasks_cache[task_id] = task
    return task


@app.get("/tasks/{task_id}", response_model=TaskResponse)
async def get_task(task_id: str):
    task = tasks_cache.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return task
