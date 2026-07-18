.PHONY: smoke adversarial up down logs clean schema test-mitm help

help:
	@echo "Targets: up | down | smoke | adversarial | schema | test-mitm | logs | clean"

up:
	docker compose -f deploy/compose.yaml up -d --build

down:
	docker compose -f deploy/compose.yaml down -v

logs:
	docker compose -f deploy/compose.yaml logs --tail=100

schema:
	python3 classifier/validate_profiles.py

test-mitm:
	python3 deploy/mitm/mitm_test.py

smoke: schema up
	python3 classifier/run_smoke.py --compose-file deploy/compose.yaml

# DNS-02: MITM overlay. Does not replace smoke.
adversarial: schema test-mitm
	python3 classifier/run_adversarial.py

clean: down
	rm -rf artifacts/smoke-* artifacts/adversarial-*
