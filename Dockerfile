FROM vllm/vllm-openai:qwen38-x86_64-cu130
COPY requirements-platform.txt /tmp/requirements-platform.txt
RUN python3 -m pip install --no-cache-dir -r /tmp/requirements-platform.txt
WORKDIR /workspace
ENTRYPOINT ["python3", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8092"]
