FROM python:3.12-slim
# Lie le package GHCR au repo : sans ce label, GitHub le crée sous le compte
# sans le rattacher (page pkgs/ du repo en 404).
LABEL org.opencontainers.image.source=https://github.com/noirebox/noirebox
WORKDIR /srv
COPY requirements.txt .
# pip d'abord : l'emb pip 25.0.1 de la base traîne des CVE fixables —
# et un rebuild régulier sur base fraîche purge les CVEs Debian (zlib, perl…).
RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt
COPY noirebox/ noirebox/
COPY corpus/ corpus/
# Les micro-modèles embarquent dans l'image : le moteur ML fonctionne
# out of the box (ml_guardrail les cherche dans /srv/models via _ROOT).
COPY models/ models/
# Le vérificateur tiers voyage avec l'image : l'auditeur peut vérifier
# un export avec le même outil que le producteur.
COPY verifier/ verifier/
# NB-09 : uvicorn ne tourne pas en root. Utilisateur système dédié, sans
# shell, propriétaire de /srv (le journal et sa clé y vivent en 0600 —
# root de moins dans la chaîne, pas un de plus).
RUN useradd -r -u 10001 -m noirebox \
    && mkdir -p /srv/data \
    && chown -R noirebox:noirebox /srv
USER noirebox
EXPOSE 8768
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8768/api/v1/verify')" || exit 1
CMD ["uvicorn", "noirebox.main:app", "--host", "0.0.0.0", "--port", "8768"]
