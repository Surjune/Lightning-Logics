# Deploying the public demo

The product runs **on-premises** inside the enclave. This page is only for the optional public
demo — a browser link where a reviewer can upload a capture and see the analysis. It uses the
[`Dockerfile`](../Dockerfile) at the repo root (statistical detectors only, so nothing mis-fires on
the synthetic sample) and honours the `PORT` the host injects.

Recommended host: **AWS App Runner** (always-on, auto-HTTPS, WebSockets) with a **free custom domain**
from the GitHub Student Developer Pack, so the URL is your own — no platform brand, no cold start.

---

## 1 · Push the image to Amazon ECR

```bash
# vars
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
REGION=us-east-1
REPO=enclave-demo

# create the registry once
aws ecr create-repository --repository-name $REPO --region $REGION

# build and push
aws ecr get-login-password --region $REGION \
  | docker login --username AWS --password-stdin $ACCOUNT.dkr.ecr.$REGION.amazonaws.com
docker build -t $REPO .
docker tag  $REPO:latest $ACCOUNT.dkr.ecr.$REGION.amazonaws.com/$REPO:latest
docker push               $ACCOUNT.dkr.ecr.$REGION.amazonaws.com/$REPO:latest
```

## 2 · Create the App Runner service

Console → **App Runner** → **Create service**:

1. **Source**: Container registry → Amazon ECR → browse to the `enclave-demo:latest` image.
2. **Deployment**: Manual (or Automatic to redeploy on every push).
3. **Port**: `8000`. No extra environment variables are required (`PORT` is set for you).
4. **CPU/Memory**: 1 vCPU / 2 GB is plenty (the models are ~2 MB).
5. Create. After a few minutes you get a URL like
   `https://<id>.<region>.awsapprunner.com` — test it, then attach your own domain below.

App Runner keeps at least one instance provisioned, so there is **no per-request cold start** — your
AWS credits cover the always-on cost.

> Simpler alternative: **Lightsail Containers**. `aws lightsail push-container-image` uploads the
> local build directly (no ECR), a flat ~$7/mo from credits, custom domains + free SSL included.

## 3 · Get a free custom domain (GitHub Student Pack)

1. Go to <https://education.github.com/pack> → find **Namecheap** (free `.me` for one year) or
   **Name.com** / **.tech**.
2. Redeem and register a **generic** name — e.g. `enclave-monitor.me`. **Do not** put the problem
   number or anything that identifies the project in the name (opponents can find public records).

## 4 · Point the domain at App Runner

App Runner service → **Custom domains** → **Add domain** → enter `enclave-monitor.me`:

1. App Runner shows a set of **DNS records** (a certificate-validation CNAME plus the target).
2. In Namecheap → **Advanced DNS**, add those records exactly as shown.
3. Wait for validation (minutes to an hour). App Runner then issues HTTPS automatically.

Your reviewer link is now:

```
https://enclave-monitor.me
```

No `amazonaws.com`, no cold start, HTTPS. Done.

---

## Notes

- **WebSockets** power the live feed; App Runner, Lightsail Containers, ECS Fargate and EC2 all
  support them. The dashboard also falls back to 2-second polling if a WebSocket can't connect, so
  the demo still works on hosts with weak WebSocket support.
- **Not Vercel / not serverless.** The demo is a long-running process with an in-memory alert store
  and a streaming pipeline; serverless functions (no persistent process, no WebSockets, short
  timeouts) can host the static page but not the engine.
- **Cost control.** Delete the App Runner service (or stop the Lightsail container) after judging to
  stop spending credits.
