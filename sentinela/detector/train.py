"""RF1: treina o classificador de payloads (5 classes) e salva modelo + métricas + matriz de confusão."""
import csv
import json
import os
import sys

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from normalize import normalize  # noqa: E402

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def carregar(caminho):
    valores, rotulos = [], []
    with open(caminho, newline="", encoding="utf-8") as f:
        for linha in csv.DictReader(f):
            valores.append(linha["value"])
            rotulos.append(linha["label"].strip().lower())
    return valores, rotulos


def montar_pipeline():
    return Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), preprocessor=normalize, sublinear_tf=True)),
        ("lr", LogisticRegression(class_weight="balanced", max_iter=1000)),
    ])


def treinar(csv_path, saida):
    X, y = carregar(csv_path)
    # stratify exige >=2 exemplos por classe; com menos, o split falha cedo e claro.
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
    pipe = montar_pipeline().fit(Xtr, ytr)
    pred = pipe.predict(Xte)
    classes = sorted(set(y))
    rep = classification_report(yte, pred, labels=classes, output_dict=True, zero_division=0)
    cm = confusion_matrix(yte, pred, labels=classes)
    metricas = {
        "acuracia": rep["accuracy"],
        "macro_f1": f1_score(yte, pred, average="macro"),
        "por_classe": {c: {"precisao": rep[c]["precision"], "recall": rep[c]["recall"]} for c in classes},
        "classes": classes,
        "matriz_confusao": cm.tolist(),
        "n_treino": len(Xtr), "n_teste": len(Xte),
    }
    os.makedirs(saida, exist_ok=True)
    joblib.dump(pipe, os.path.join(saida, "classifier.joblib"))
    with open(os.path.join(saida, "metrics.json"), "w") as f:
        json.dump(metricas, f, indent=2, ensure_ascii=False)
    _png(cm, classes, os.path.join(saida, "confusion.png"))
    return metricas


def _png(cm, classes, caminho):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(6, 5))
    ax.imshow(cm, cmap="Blues")
    ax.set_xticks(range(len(classes)), classes, rotation=45)
    ax.set_yticks(range(len(classes)), classes)
    ax.set_xlabel("previsto")
    ax.set_ylabel("real")
    for i in range(len(classes)):
        for j in range(len(classes)):
            ax.text(j, i, cm[i][j], ha="center", va="center", color="white" if cm[i][j] > cm.max() / 2 else "black")
    fig.tight_layout()
    fig.savefig(caminho, dpi=150)
    plt.close(fig)


if __name__ == "__main__":
    caminho = os.path.join(RAIZ, "data", "train.csv")
    if not os.path.exists(caminho):
        sys.exit(f"Sem {caminho}: coloque o CSV do time (colunas value,label).")
    m = treinar(caminho, os.path.join(RAIZ, "models"))
    print(f"acurácia={m['acuracia']:.4f}  macro-F1={m['macro_f1']:.4f}")
    for c, v in m["por_classe"].items():
        print(f"  {c:10s} precisão={v['precisao']:.3f} recall={v['recall']:.3f}")
    print(m["classes"])
    for linha in m["matriz_confusao"]:
        print(linha)
