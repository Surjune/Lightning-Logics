# Deployment

The core product is designed to run **on-premises, offline**, inside the monitoring enclave
(air-gapped, no cloud, no outbound path — see the PS threat model). The instructions below cover
both that primary case and the optional **public demo link** an evaluator can click.

## 1. Local run (primary — this is the product)

```bash
python -m venv .venv
# Windows:  .venv\Scripts\activate     Linux/macOS:  source .venv/bin/activate
pip install -e ".[dev]"

enclave synth --out data/demo.pcap --intel intel                 # labelled demo capture
enclave replay data/demo.pcap --speed 6 --config config/enclave.example.json --serve
# open http://127.0.0.1:8000
```

Nothing leaves the machine. The `egress_guard` blocks any outbound connection at process level,
so the read-only constraint holds even if a dependency tried to phone home.

## 2. Public demo link (optional — so evaluators can try it without cloning)

The demo server serves the dashboard **and** a file-upload endpoint: the evaluator uploads a
`.pcap`/`.pcapng`, the pipeline analyses it, and the alerts appear on the dashboard. A labelled
sample is one click away (**Download sample**), so there is always something to upload.

The image is host-agnostic. Build once, deploy anywhere:

```bash
docker build -t enclave-console .
docker run -p 8000:8000 enclave-console          # http://localhost:8000
```

| Host | How | Notes |
| --- | --- | --- |
| **Hugging Face Spaces** (free) | New Space -> SDK **Docker** -> push this repo. Set `app_port: 8000`. | Free, permanent public URL, no credit card. Simplest. |
| **AWS App Runner** | Create service from this image (ECR or source). Port 8000. | The "enterprise" option; needs an AWS account. Charges apply. |
| **AWS ECS/Fargate** | Task def with this image, ALB on port 8000. | Most control, most setup. |
| **Render / Railway** | New Web Service from the repo (Docker). They inject `$PORT`, which the CMD honours. | Free tier sleeps when idle. |

Only the demo server is exposed. It never reaches back into any production network, and the upload
path writes each capture to a temporary file that is deleted after analysis.

### Deploy note (public demo runs statistical detectors only)

The public sample capture is **synthetic**, so the supervised model is intentionally left off in
the image (a model trained on CIC-IDS2017 would mis-fire on a different distribution). The six
statistical detectors run and every threat class fires. To demonstrate the ML layer, run locally
against real traffic with a trained model — see [`ml/README.md`](../ml/README.md).

## 3. Running it 24/7 (always-on monitoring)

The product is a continuously running service, not a page you launch per request. The detection
engine runs non-stop; the dashboard is just a window into it, and alerts keep landing in the
hash-chained log whether or not anyone is watching.

**Docker Compose** (restarts on crash and on host reboot):

```bash
docker compose up -d          # start; runs continuously
docker compose logs -f        # watch
docker compose ps             # status / health
```

**systemd** (bare-metal enclave host):

```bash
sudo cp deploy/enclave.service /etc/systemd/system/
sudo systemctl enable --now enclave     # starts now and on every boot; Restart=always
sudo systemctl status enclave
```

In production, change `ExecStart` from the upload server to the live capture feed
(`enclave sniff --iface eth1 --serve`), so the service consumes the diode's mirror directly.

## 4. Enabling the supervised ML layer

```bash
pip install -e ".[train]"
# download CIC-IDS2017 flow CSVs into data/cicids2017/ (see ml/README.md), then:
python ml/train.py --csv-dir data/cicids2017
enclave replay <capture>.pcap --config config/enclave.ml.example.json --serve
```

`config/enclave.ml.example.json` sets `ml_model_dir`, which switches the `ml-flow` detector on.
Without it, the detector reports itself off on the dashboard and the statistical detectors run alone.
