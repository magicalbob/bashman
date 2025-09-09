# perf_publish.py
import asyncio, httpx, os, time, uuid, statistics

BASE = os.getenv("BASHMAN_BASE", "http://127.0.0.1:8000")
N = int(os.getenv("N", "200"))                 # total packages
CONC = int(os.getenv("CONC", "50"))            # concurrency
POLL = float(os.getenv("POLL", "0.2"))         # seconds between polls
TIMEOUT = float(os.getenv("TIMEOUT", "30"))    # per-package timeout seconds

SCRIPT = b"""#!/usr/bin/env bash
echo hello
"""

def percentiles(samples, ps=(50,90,95,99)):
    if not samples: return {}
    xs = sorted(samples)
    out = {}
    for p in ps:
        k = max(0, min(len(xs)-1, int(round((p/100) * (len(xs)-1)))))
        out[p] = xs[k]
    return out

async def upload_and_wait(client: httpx.AsyncClient, name: str):
    t0 = time.perf_counter()
    data = {
        "name": name,
        "version": "0.1.0",
        "description": f"perf {name}",
        "keywords": "[]",
        "dependencies": "{}",
        "platforms": "[]",
    }
    files = {"file": ("s.sh", SCRIPT, "text/plain")}
    r = await client.post(f"{BASE}/api/packages", data=data, files=files)
    r.raise_for_status()
    # Poll until published
    deadline = time.perf_counter() + TIMEOUT
    while True:
        g = await client.get(f"{BASE}/api/packages/{name}")
        if g.status_code == 200:
            if g.json().get("status") == "published":
                return time.perf_counter() - t0
        if time.perf_counter() > deadline:
            raise TimeoutError(f"{name} not published within {TIMEOUT}s")
        await asyncio.sleep(POLL)

async def main():
    limits = httpx.Limits(max_connections=CONC, max_keepalive_connections=CONC)
    async with httpx.AsyncClient(timeout=10, limits=limits) as client:
        sem = asyncio.Semaphore(CONC)
        results = []
        errors = []

        async def one(i):
            name = f"perf-{uuid.uuid4().hex[:8]}-{i}"
            async with sem:
                try:
                    dt = await upload_and_wait(client, name)
                    results.append(dt)
                except Exception as e:
                    errors.append((name, str(e)))

        t_start = time.perf_counter()
        await asyncio.gather(*(one(i) for i in range(N)))
        wall = time.perf_counter() - t_start

    ok = len(results); err = len(errors)
    print(f"\nRan {N} uploads at CONC={CONC} in {wall:.2f}s: ok={ok}, err={err}")
    if results:
        avg = statistics.fmean(results)
        p = percentiles(results)
        print(f"Throughput: {ok / wall:.2f} pkg/s")
        print(f"Latency sec  avg={avg:.3f}  p50={p.get(50,0):.3f}  p90={p.get(90,0):.3f}  "
              f"p95={p.get(95,0):.3f}  p99={p.get(99,0):.3f}")

    if errors:
        print("\nErrors (first 5):")
        for n, e in errors[:5]:
            print(f"  {n}: {e}")

if __name__ == "__main__":
    asyncio.run(main())
