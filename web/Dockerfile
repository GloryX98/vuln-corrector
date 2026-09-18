# Container for the browser UI. Build from the repo root:
#   docker build -t vuln-corrector-web -f web/Dockerfile .
#   docker run --rm -p 8000:8000 vuln-corrector-web
# Then open http://localhost:8000
FROM python:3.12-slim

WORKDIR /app
# openpyxl is only needed for .xlsx uploads; HTTP uses the standard library.
RUN pip install --no-cache-dir openpyxl

# The web app imports the sibling module, so copy both.
COPY vuln_corrector.py /app/vuln_corrector.py
COPY web/app.py /app/web/app.py

ENV HOST=0.0.0.0 PORT=8000
EXPOSE 8000
CMD ["python", "web/app.py"]
