# ImpactGuard (Streamlit)
A Streamlit app that calls the Poe API to generate adversarial prompts, execute attacks, score pass/fail, and render a dashboard with severity & framework alignment.

## Run locally
```bash
pip install -r requirements.txt
# Set your Poe key (recommended via env var)
export POE_API_KEY="sk-..."
streamlit run app.py
```
Open the local URL printed by Streamlit.

## Docker
```bash
docker build -t impactguard-streamlit .
docker run -p 8501:8501 -e POE_API_KEY="sk-..." impactguard-streamlit
# open http://localhost:8501
```

## Notes
- Level n sends 2^n prompts.
- Pass/Fail + Critical/High/Medium/Low calc is heuristic; adapt to your policies.
- For production, set `POE_API_KEY` and optionally `POE_BASE_URL` and `IG_MODEL` in environment.
