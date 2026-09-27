"""
SHAP Explainer
Generates SHAP-based explanations for individual URL predictions
and produces feature-importance bar charts.
"""

import sys
import io
import base64
import warnings
from pathlib import Path

import joblib
import numpy as np
import matplotlib
matplotlib.use("Agg")          # non-interactive backend
import matplotlib.pyplot as plt
import shap

warnings.filterwarnings("ignore")

ROOT      = Path(__file__).parent.parent
MODEL_DIR = ROOT / "models"
sys.path.insert(0, str(Path(__file__).parent))

from feature_extractor import FEATURE_NAMES, get_feature_descriptions


# ── SHAP Explainer wrapper ────────────────────────────────────────────────────

class PhishingExplainer:
    """
    Wraps a trained model with a SHAP TreeExplainer (or KernelExplainer
    fallback) to produce per-prediction explanations.
    """

    def __init__(self, model=None, model_name: str = "ensemble"):
        if model is None:
            path = MODEL_DIR / f"{model_name}.pkl"
            if not path.exists():
                raise FileNotFoundError(
                    f"Model not found at {path}. Run train_model.py first."
                )
            model = joblib.load(path)

        self.model      = model
        self.model_name = model_name
        self._explainer = None
        self._build_explainer()

    # ── Internal ──────────────────────────────────────────────────────────────

    def _build_explainer(self):
        """Build the appropriate SHAP explainer for the loaded model."""
        try:
            # TreeExplainer works for RF, XGB and Voting ensembles
            self._explainer = shap.TreeExplainer(self.model)
            self._kind = "tree"
        except Exception:
            # Fallback: use a small background sample
            bg = np.zeros((10, len(FEATURE_NAMES)))
            self._explainer = shap.KernelExplainer(
                self.model.predict_proba, bg
            )
            self._kind = "kernel"

    def _get_shap_values(self, X: np.ndarray):
        """
        Return SHAP values for the phishing class (index 1).
        Handles both old and new SHAP API shapes.
        """
        raw = self._explainer.shap_values(X)

        # shap_values may be:
        #   list of 2 arrays  → [class0_vals, class1_vals]
        #   single 3-D array  → shape (n_samples, n_features, n_classes)
        #   single 2-D array  → already class-1 values
        if isinstance(raw, list):
            vals = raw[1]                          # phishing class
        elif isinstance(raw, np.ndarray) and raw.ndim == 3:
            vals = raw[:, :, 1]
        else:
            vals = raw
        return vals

    # ── Public API ────────────────────────────────────────────────────────────

    def explain(self, features: dict) -> dict:
        """
        Generate a full explanation for one URL's feature dict.

        Returns
        -------
        dict with keys:
          shap_values     – list of (feature_name, shap_value, feature_value)
          base_value      – SHAP base (expected) value
          prediction_prob – model's predicted probability of phishing
          top_contributors – top-5 features driving the prediction
          chart_b64       – base64-encoded PNG of the SHAP bar chart
        """
        X = np.array([features[n] for n in FEATURE_NAMES]).reshape(1, -1)

        shap_vals = self._get_shap_values(X)[0]   # 1-D, one per feature

        # Base value (expected value for phishing class)
        ev = self._explainer.expected_value
        if isinstance(ev, (list, np.ndarray)):
            base_value = float(ev[1]) if len(ev) > 1 else float(ev[0])
        else:
            base_value = float(ev)

        # Prediction probability
        if hasattr(self.model, "predict_proba"):
            prob = float(self.model.predict_proba(X)[0][1])
        else:
            prob = float(self.model.predict(X)[0])

        # Build named list
        named = [
            {
                "feature":     name,
                "shap_value":  round(float(sv), 6),
                "feature_value": round(float(features[name]), 4),
                "description": get_feature_descriptions().get(name, ""),
            }
            for name, sv in zip(FEATURE_NAMES, shap_vals)
        ]

        # Sort by absolute impact
        named_sorted = sorted(named, key=lambda x: abs(x["shap_value"]), reverse=True)

        top5 = named_sorted[:5]

        # Generate chart
        chart_b64 = self._render_bar_chart(named_sorted[:15], prob)

        return {
            "shap_values":       named_sorted,
            "base_value":        round(base_value, 6),
            "prediction_prob":   round(prob, 4),
            "top_contributors":  top5,
            "chart_b64":         chart_b64,
        }

    def _render_bar_chart(self, named_sorted: list, prob: float) -> str:
        """Render a horizontal bar chart and return it as base64 PNG."""
        items  = named_sorted[:15]
        names  = [i["feature"] for i in items]
        values = [i["shap_value"] for i in items]
        colors = ["#e74c3c" if v > 0 else "#2ecc71" for v in values]

        fig, ax = plt.subplots(figsize=(9, 5))
        bars = ax.barh(names[::-1], values[::-1], color=colors[::-1],
                       edgecolor="none", height=0.6)

        ax.axvline(0, color="#555", linewidth=0.8, linestyle="--")
        ax.set_xlabel("SHAP Value  (positive → phishing, negative → legitimate)",
                      fontsize=9)
        ax.set_title(
            f"Feature Contributions  |  Phishing Probability: {prob:.1%}",
            fontsize=11, fontweight="bold", pad=12
        )
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        plt.tight_layout()

        buf = io.BytesIO()
        fig.savefig(buf, format="png", dpi=120, bbox_inches="tight")
        plt.close(fig)
        buf.seek(0)
        return base64.b64encode(buf.read()).decode("utf-8")

    def global_importance_chart(self) -> str:
        """
        Generate a global feature importance chart from the model
        (uses RF feature_importances_ if available, else uniform).
        Returns base64 PNG.
        """
        importances = None
        # Try ensemble sub-estimators
        if hasattr(self.model, "estimators_"):
            for name, est in self.model.estimators_:
                if hasattr(est, "feature_importances_"):
                    importances = est.feature_importances_
                    break
        if importances is None and hasattr(self.model, "feature_importances_"):
            importances = self.model.feature_importances_

        if importances is None:
            importances = np.ones(len(FEATURE_NAMES)) / len(FEATURE_NAMES)

        idx   = np.argsort(importances)[-15:]
        names = [FEATURE_NAMES[i] for i in idx]
        vals  = importances[idx]

        fig, ax = plt.subplots(figsize=(9, 5))
        ax.barh(names, vals, color="#3498db", edgecolor="none", height=0.6)
        ax.set_xlabel("Feature Importance", fontsize=9)
        ax.set_title("Global Feature Importances (Top 15)", fontsize=11,
                     fontweight="bold", pad=12)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        plt.tight_layout()

        buf = io.BytesIO()
        fig.savefig(buf, format="png", dpi=120, bbox_inches="tight")
        plt.close(fig)
        buf.seek(0)
        return base64.b64encode(buf.read()).decode("utf-8")
