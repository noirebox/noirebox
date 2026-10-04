# NoireBox — shortcuts (make test, make demo, make serve…)
.PHONY: install test bench serve demo demo-mcp demo-llm demo-judge demo-fleet demo-payout ollama-pull judge-pull tsa dataset train train-en docker clean

install:
	python3 -m venv .venv
	.venv/bin/pip install -q --upgrade pip
	.venv/bin/pip install -q -r requirements.txt

test:
	.venv/bin/pytest -q

bench:
	.venv/bin/python demo/bench.py

serve:
	.venv/bin/uvicorn noirebox.main:app --host 127.0.0.1 --port 8768

demo:
	.venv/bin/python demo/demo_live.py

demo-mcp:
	.venv/bin/python demo/demo_mcp.py

demo-llm:
	.venv/bin/python demo/demo_ollama.py

demo-judge:
	.venv/bin/python demo/demo_judge.py

judge-pull:
	ollama pull llama-guard3:1b

demo-fleet:
	.venv/bin/python demo/demo_fleet.py

demo-payout:
	.venv/bin/python demo/demo_payout.py

ollama-pull:
	ollama pull qwen2.5:0.5b

tsa:
	@chmod +x tsa/gen_tsa.sh && ./tsa/gen_tsa.sh tsa/material
	.venv/bin/python tsa/tsa_server.py --material tsa/material --port 3318

dataset:
	.venv/bin/python ml/gen_dataset.py

train:
	.venv/bin/python ml/gen_dataset.py
	.venv/bin/python ml/train.py

train-en:
	.venv/bin/python ml/gen_dataset_en.py
	.venv/bin/python ml/train.py --lang en

docker:
	docker compose up --build

clean:
	rm -rf data/*.db data/*.key .pytest_cache
	find . -name __pycache__ -type d -exec rm -rf {} +
