// Forest manifest for grund's control plane (the dashboard and API).
//
// Deployed to the existing homelab clusters through the kjuulh
// organisation's Flux destinations, the path grund/website and the tiny
// services use, until grund runs on its own platform. Nothing here is
// specific to those clusters beyond the destination names: the image is a
// scratch binary with PostgreSQL as its only required dependency.
//
// CI rolls every main commit to dev through the project's dev trigger.
// Production is a deliberate promotion by Kasper; nothing here does it.
package grund

project: {
	name:         "grund"
	organisation: "kjuulh"
	description:  "grund's control plane: the dashboard, the API and the work behind them."
}

_destinationTypes: {
	flux: "forest/flux@1"
}

dependencies: {
	"forest/deployment": version:        "0.3.0"
	"kjuulh/kubernetes-app": version:    "0.1.13"
	"kjuulh/woodpecker-forest": version: "0.1.10"
}

forest: deployment: enabled: true

kjuulh: "kubernetes-app": {
	env: {
		dev: {
			destinations: [
				{destination: "flux-dev.*", type: _destinationTypes.flux},
			]
			config: {
				namespace: "dev"
				host:      "dev.app.grund.sh"
				replicas:  1
				env_vars: {
					GRUND_PUBLIC_URL: "https://dev.app.grund.sh"
					GRUND_MAIL_FROM:  "grund dev <grund@dev.app.grund.sh>"
				}
				// grund-secrets is applied by the cluster's operators, not by
				// forest. Dev's smtp_url is the namespace's shared development
				// mailbox, which delivers nowhere.
				secret_env: [
					{name: "DATABASE_URL", secret: "grund-db-app", key: "uri"},
					{name: "GRUND_SECRET_KEY", secret: "grund-secrets", key: "secret_key"},
					{name: "GRUND_SMTP_URL", secret: "grund-secrets", key: "smtp_url"},
				]
			}
		}

		prod: {
			destinations: [
				{destination: "flux-prod.*", type: _destinationTypes.flux},
			]
			config: {
				namespace: "prod"
				host:      "app.grund.sh"
				replicas:  2
				env_vars: {
					GRUND_PUBLIC_URL: "https://app.grund.sh"
				}
				// No grund-secrets in prod yet: it needs a real mail provider
				// first. Add GRUND_SECRET_KEY and GRUND_SMTP_URL here, as in
				// dev, before the first promotion; without a key grund refuses
				// to start, naming GRUND_SECRET_KEY.
				secret_env: [
					{name: "DATABASE_URL", secret: "grund-db-app", key: "uri"},
				]
			}
		}
	}

	config: {
		name:  "grund"
		image: "git.kjuulh.io/grund/grund"
		// Overridden on every release with the main-<sha> tag CI published.
		// No image is ever tagged "main", so a render without the override
		// fails to pull instead of running something unknown.
		tag: "main"

		ports: [
			{name: "http", port: 8080},
		]

		env_vars: {
			GRUND_LISTEN:     "0.0.0.0:8080"
			GRUND_LOG_FORMAT: "json"
			RUST_LOG:         "grund=info,grund_server=info,grund_store=info,notmad=info,warn"
			// The ingress controller is the one proxy that appends to
			// X-Forwarded-For. The edge in front of it forwards TLS without
			// passing the client address on, so every request arrives from the
			// same address: the per-address limits would throttle everyone
			// together, and are off until the client address is preserved.
			// Per-account limits apply regardless.
			GRUND_TRUSTED_PROXY_HOPS:         "1"
			GRUND_LOGIN_ATTEMPTS_PER_ADDRESS: "0"
			GRUND_MAIL_REQUESTS_PER_ADDRESS:  "0"
			// No NATS in these clusters for grund yet: background work is
			// found by polling, which is correct on its own.
			GRUND_WORK_POLL_INTERVAL: "2"
		}

		postgres: {
			instances:    1
			storage_size: "5Gi"
			database:     "grund"
			owner:        "grund"
			backup: {
				enabled:  true
				schedule: "0 45 2 * * *"
			}
		}

		// Sign-in hashes a password with Argon2id at 19 MiB per hash, at most
		// four at once, so memory has room for that
		// above the baseline.
		resources: {
			requests: {
				cpu:    "50m"
				memory: "64Mi"
			}
			limits: {
				cpu:    "1"
				memory: "256Mi"
			}
		}

		// Readiness reports the build revision and whether PostgreSQL answers;
		// liveness checks nothing, so a database outage takes replicas out of
		// rotation without restarting them.
		health: {
			path:                  "/health/ready"
			liveness_path:         "/health/live"
			port:                  "http"
			initial_delay_seconds: 3
			period_seconds:        10
			timeout_seconds:       3
			failure_threshold:     6
		}
	}
}

// Generates .woodpecker/rollout.yaml (`forest run install`). The manual
// production job is off: production promotion belongs to Kasper, through
// forest, never to CI. `server` is the forest instance's gRPC endpoint,
// pinned so a change of component default cannot move releases elsewhere.
kjuulh: "woodpecker-forest": config: {
	server:          "https://api.forest.kjuulh.io"
	artifact_image:  "git.kjuulh.io/grund/grund"
	manual_prod_job: false
}

commands: {
	check: ["./check.sh"]
	serve: ["cargo run -p grund -- serve --dev-mode true --database-url postgres://grund:grund@127.0.0.1:55410/grund"]
}
