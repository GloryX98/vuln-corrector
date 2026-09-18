# Container for the browser UI. Build from the repo root:
#   docker build -t vuln-corrector-web -f web/Dockerfile .
#   docker run --rm -p 8000:8000 vuln-corrector-web
# Then open http://localhost:8000
FROM python:3.12-slim

WORKDIR /app
# openpyxl is only needed for .xlsx uploads; HTTP uses the standard library.
RUN pip install --no-cache-dir openpyxl

COPY vuln_corrector.py /app/vuln_corrector.py
COPY webui.py /app/webui.py

# In a container, listen on all interfaces on the platform-provided port.
ENV HOST=0.0.0.0 PORT=8000
EXPOSE 8000
CMD ["python", "webui.py"]
