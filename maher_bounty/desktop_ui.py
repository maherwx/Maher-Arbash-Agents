"""Maher local desktop: forms mirror the authoritative CLI parser."""
import argparse
import codecs
import os
import queue
import shlex
import subprocess
import sys
import threading
from pathlib import Path

from .process_runtime import run, ProcessCancelled, OutputLimitExceeded


OPERATION_GROUPS = {
    "run": "\u0627\u0644\u0641\u062d\u0635", "auto-run": "\u0627\u0644\u0641\u062d\u0635", "agent-tools-run": "\u0627\u0644\u0641\u062d\u0635",
    "workflow-run": "\u0627\u0644\u0635\u0644\u0627\u062d\u064a\u0627\u062a \u0648\u0633\u064a\u0631 \u0627\u0644\u0639\u0645\u0644", "policy-agents-run": "\u0627\u0644\u0635\u0644\u0627\u062d\u064a\u0627\u062a \u0648\u0633\u064a\u0631 \u0627\u0644\u0639\u0645\u0644",
    "api-contract-review": "\u0627\u0644\u0635\u0644\u0627\u062d\u064a\u0627\u062a \u0648\u0633\u064a\u0631 \u0627\u0644\u0639\u0645\u0644",
    "source-review": "\u0627\u0644\u0643\u0648\u062f \u0648\u062d\u0631\u0643\u0629 \u0627\u0644\u0645\u0631\u0648\u0631", "traffic-import": "\u0627\u0644\u0643\u0648\u062f \u0648\u062d\u0631\u0643\u0629 \u0627\u0644\u0645\u0631\u0648\u0631",
    "traffic-analyze": "\u0627\u0644\u0643\u0648\u062f \u0648\u062d\u0631\u0643\u0629 \u0627\u0644\u0645\u0631\u0648\u0631",
    "inventory": "\u0627\u0644\u062a\u0642\u0627\u0631\u064a\u0631 \u0648\u0627\u0644\u062e\u062f\u0645\u0629", "serve": "\u0627\u0644\u062a\u0642\u0627\u0631\u064a\u0631 \u0648\u0627\u0644\u062e\u062f\u0645\u0629",
    "service-status": "\u0627\u0644\u062a\u0642\u0627\u0631\u064a\u0631 \u0648\u0627\u0644\u062e\u062f\u0645\u0629",
    "doctor": "\u0627\u0644\u0623\u062f\u0648\u0627\u062a \u0648\u0627\u0644\u0625\u0639\u062f\u0627\u062f", "workflow-benchmark": "\u0627\u0644\u0623\u062f\u0648\u0627\u062a \u0648\u0627\u0644\u0625\u0639\u062f\u0627\u062f",
}
OPERATION_LABELS = {
    "run": "\u062a\u0634\u063a\u064a\u0644 \u0645\u0633\u0627\u0631 \u0627\u0644\u0648\u0643\u0644\u0627\u0621", "auto-run": "\u0627\u0643\u062a\u0634\u0627\u0641 \u0648\u0641\u062d\u0635 \u0645\u0648\u0642\u0639",
    "agent-tools-run": "\u062a\u0634\u063a\u064a\u0644 \u0623\u062f\u0648\u0627\u062a \u0627\u0644\u0641\u062d\u0635", "workflow-run": "\u0627\u062e\u062a\u0628\u0627\u0631 \u0633\u064a\u0631 \u0627\u0644\u0639\u0645\u0644",
    "policy-agents-run": "\u0627\u062e\u062a\u0628\u0627\u0631 \u0635\u0644\u0627\u062d\u064a\u0627\u062a \u0627\u0644\u062d\u0633\u0627\u0628\u0627\u062a", "api-contract-review": "\u0645\u0631\u0627\u062c\u0639\u0629 \u0645\u0644\u0641 OpenAPI",
    "source-review": "\u0645\u0631\u0627\u062c\u0639\u0629 \u0643\u0648\u062f \u0645\u062d\u0644\u064a", "traffic-import": "\u0627\u0633\u062a\u064a\u0631\u0627\u062f Burp \u0623\u0648 HAR",
    "traffic-analyze": "\u062a\u062d\u0644\u064a\u0644 \u062d\u0631\u0643\u0629 \u0645\u062d\u0641\u0648\u0638\u0629", "inventory": "\u0628\u0646\u0627\u0621 \u0642\u0627\u0626\u0645\u0629 \u0627\u0644\u0623\u0635\u0648\u0644",
    "serve": "\u0645\u0631\u0627\u0642\u0628\u0629 \u0645\u062c\u0644\u062f \u0628\u0627\u0633\u062a\u0645\u0631\u0627\u0631", "service-status": "\u0639\u0631\u0636 \u062d\u0627\u0644\u0629 \u0627\u0644\u062e\u062f\u0645\u0629",
    "doctor": "\u0641\u062d\u0635 \u0627\u0644\u0623\u062f\u0648\u0627\u062a \u0627\u0644\u0645\u062b\u0628\u062a\u0629", "workflow-benchmark": "\u0645\u0642\u064a\u0627\u0633 \u0645\u062d\u0644\u064a",
}
OPERATION_DESCRIPTIONS = {
    "run": "\u064a\u0634\u063a\u0651\u0644 \u0627\u0644\u0648\u0643\u0644\u0627\u0621 \u0648\u064a\u0646\u0641\u0630 \u0627\u0644\u0641\u062d\u0635 \u062d\u0633\u0628 \u0645\u0644\u0641\u064a \u0627\u0644\u0646\u0637\u0627\u0642 \u0648\u0627\u0644\u0642\u0648\u0627\u0639\u062f.",
    "auto-run": "\u064a\u062c\u0645\u0639 \u0627\u0644\u0623\u0635\u0648\u0644 \u0627\u0644\u0645\u062a\u0627\u062d\u0629 \u062b\u0645 \u064a\u0634\u063a\u0651\u0644 \u0627\u0644\u0641\u062d\u0635. \u064a\u0631\u0633\u0644 \u0637\u0644\u0628\u0627\u062a \u0644\u0644\u0647\u062f\u0641 \u0627\u0644\u0645\u0635\u0631\u0651\u062d \u0628\u0647.",
    "agent-tools-run": "\u064a\u0634\u063a\u0651\u0644 \u0645\u062d\u0648\u0651\u0644\u0627\u062a \u0645\u062d\u0644\u064a\u0629 \u0645\u062d\u062f\u062f\u0629 \u0644\u0644\u0646\u0637\u0627\u0642. \u0627\u062e\u062a\u0631 \u0645\u062c\u0645\u0648\u0639\u0629 \u0627\u0644\u0648\u064a\u0628 \u0623\u0648 \u0627\u0643\u062a\u0634\u0627\u0641 \u0627\u0644\u0645\u0633\u0627\u0631\u0627\u062a \u0623\u0648 \u0627\u0644\u0634\u0628\u0643\u0629/TLS \u0623\u0648 \u062c\u0645\u064a\u0639 \u0627\u0644\u0623\u062f\u0648\u0627\u062a. \u064a\u0634\u063a\u0651\u0644 \u0627\u0644\u0645\u0646\u0633\u0651\u0642 \u0627\u0644\u0645\u062d\u0644\u064a \u0627\u0644\u0645\u062d\u0648\u0651\u0644\u0627\u062a \u0627\u0644\u0645\u062b\u0628\u062a\u0629 \u0636\u0645\u0646 \u0627\u0644\u0646\u0637\u0627\u0642; \u0644\u0627 \u064a\u0648\u0644\u0651\u062f \u0623\u0648\u0627\u0645\u0631 \u0634\u064a\u0644 \u062d\u0631\u0629.",
    "workflow-run": "\u064a\u0646\u0641\u0630 \u0627\u0644\u0637\u0644\u0628\u0627\u062a \u0648\u0641\u062d\u0648\u0635 \u0627\u0644\u062d\u0627\u0644\u0629 \u0627\u0644\u0645\u0643\u062a\u0648\u0628\u0629 \u0641\u064a \u0627\u0644\u0645\u0644\u0641.",
    "policy-agents-run": "\u064a\u062e\u062a\u0628\u0631 \u0635\u0644\u0627\u062d\u064a\u0627\u062a \u0627\u0644\u062d\u0633\u0627\u0628\u0627\u062a \u0627\u0644\u0645\u0632\u0648\u0651\u062f\u0629 \u0648\u0627\u0644\u0642\u0648\u0627\u0639\u062f \u0627\u0644\u0645\u0635\u0631\u0651\u062d\u0629.",
    "api-contract-review": "\u064a\u0631\u0627\u062c\u0639 \u0645\u0644\u0641 OpenAPI \u0645\u062d\u0644\u064a\u064b\u0627 \u062f\u0648\u0646 \u0625\u0631\u0633\u0627\u0644 \u0637\u0644\u0628\u0627\u062a \u0644\u0644\u0645\u0648\u0642\u0639.",
    "source-review": "\u064a\u062d\u0644\u0644 \u0645\u0644\u0641\u0627\u062a \u0627\u0644\u0643\u0648\u062f \u0627\u0644\u0645\u062d\u0644\u064a\u0629 \u062f\u0648\u0646 \u0627\u0644\u0627\u062a\u0635\u0627\u0644 \u0628\u0627\u0644\u0647\u062f\u0641.",
    "traffic-import": "\u064a\u0642\u0631\u0623 \u062a\u0635\u062f\u064a\u0631 Burp/HAR \u0645\u0648\u062c\u0648\u062f\u064b\u0627. \u0644\u0627 \u064a\u0634\u063a\u0651\u0644 Burp \u0648\u0644\u0627 \u064a\u062a\u0635\u0644 \u0628\u0627\u0644\u0645\u0648\u0642\u0639.",
    "traffic-analyze": "\u064a\u062d\u0644\u0644 \u062d\u0631\u0643\u0629 \u0645\u062d\u0641\u0648\u0638\u0629 \u0648\u064a\u0643\u062a\u0628 \u062a\u0642\u0627\u0631\u064a\u0631 \u0645\u062d\u0644\u064a\u0629.",
    "inventory": "\u064a\u0628\u0646\u064a \u0642\u0627\u0626\u0645\u0629 \u0645\u0646 \u0645\u0644\u0641\u0627\u062a \u062c\u0645\u0639 \u0633\u0627\u0628\u0642\u0629.",
    "serve": "\u064a\u0639\u0627\u0644\u062c \u0645\u0644\u0641\u0627\u062a \u0645\u062c\u0644\u062f \u0645\u062d\u0644\u064a \u0628\u0627\u0633\u062a\u0645\u0631\u0627\u0631.",
    "service-status": "\u064a\u0639\u0631\u0636 \u062d\u0627\u0644\u0629 \u062e\u062f\u0645\u0629 \u0627\u0644\u0645\u0631\u0627\u0642\u0628\u0629 \u0627\u0644\u0645\u062d\u0644\u064a\u0629.",
    "doctor": "\u064a\u0639\u0631\u0636 \u0627\u0644\u0623\u062f\u0648\u0627\u062a \u0627\u0644\u0645\u062b\u0628\u062a\u0629 \u0648\u0627\u0644\u0645\u062a\u0627\u062d\u0629.",
    "workflow-benchmark": "\u064a\u0634\u063a\u0651\u0644 \u0642\u064a\u0627\u0633\u064b\u0627 \u0645\u062d\u0644\u064a\u064b\u0627 \u0628\u062d\u0627\u0644\u0627\u062a \u0627\u062e\u062a\u0628\u0627\u0631 \u0645\u0648\u0644\u0651\u062f\u0629.",
}
OPERATION_DESCRIPTIONS["agent-tools-run"] = (
    "\u0623\u062f\u062e\u0644 \u0631\u0627\u0628\u0637\u064b\u0627 \u0636\u0645\u0646 \u0627\u0644\u0646\u0637\u0627\u0642\u060c \u0648\u0627\u062e\u062a\u0631 \u0627\u0644\u0645\u062d\u0648\u0651\u0644\u0627\u062a \u0627\u0644\u062a\u064a \u062a\u0631\u064a\u062f \u062a\u0634\u063a\u064a\u0644\u0647\u0627 \u0645\u0646 \u0627\u0644\u0642\u0627\u0626\u0645\u0629. \u0627\u062e\u062a\u0631 \u0645\u0646 \u0639\u0634\u0631\u0629 \u0645\u062d\u0648\u0651\u0644\u0627\u062a \u062b\u0627\u0628\u062a\u0629. "
    "الرابط يحدد المضيف نطاقًا تلقائيًا. ZAP والمحوّلات المثبتة تعمل مباشرة؛ Burp لا يُشغّل كفاحص تلقائي من هذا الأمر. "
    "\u0645\u0644\u0627\u062d\u0638\u0627\u062a\u0643 \u062a\u062d\u062a\u0627\u062c \u0646\u0645\u0648\u0630\u062c GGUF \u0645\u062d\u0644\u064a\u064b\u0627\u060c \u0648\u062a\u0628\u0642\u0649 \u0645\u0642\u064a\u062f\u0629 \u0628\u0627\u0644\u0623\u062f\u0648\u0627\u062a \u0648\u0627\u0644\u0642\u0648\u0627\u0644\u0628 \u0648\u0627\u0644\u0646\u0637\u0627\u0642."
)
OPERATION_DESCRIPTIONS["agent-tools-run"] = "أدخل رابطًا وأكّد الإذن. سيشغّل المنسّق المحلي المحوّلات المثبتة والمتاحة ضمن مضيف الرابط. لا تحتاج إلى ملفات؛ فحص تسجيل الدخول يحتاج هوية وسير عمل مصرّحًا بهما مسبقًا."
FIELD_LABELS = {
    "target": "\u0631\u0627\u0628\u0637 \u0627\u0644\u0645\u0648\u0642\u0639 \u0627\u0644\u0645\u0635\u0631\u0651\u062d", "targets": "\u0645\u0644\u0641 \u0631\u0648\u0627\u0628\u0637 \u0627\u0644\u0623\u0647\u062f\u0627\u0641",
    "scope": "\u0645\u0644\u0641 \u0627\u0644\u0646\u0637\u0627\u0642 \u0627\u0644\u0645\u0633\u0645\u0648\u062d", "rules": "\u0645\u0644\u0641 \u0642\u0648\u0627\u0639\u062f \u0627\u0644\u0641\u062d\u0635",
    "authorized": "\u0644\u062f\u064a \u0625\u0630\u0646 \u0644\u0641\u062d\u0635 \u0647\u0630\u0627 \u0627\u0644\u0646\u0637\u0627\u0642",
    "traffic": "ملف مرور اختياري (Burp XML / ZAP HAR)", "workflow_manifest": "\u0645\u0644\u0641 \u062e\u0637\u0648\u0627\u062a \u0627\u0644\u0627\u062e\u062a\u0628\u0627\u0631",
    "manifest": "\u0645\u0644\u0641 \u062d\u0627\u0644\u0627\u062a \u0627\u0644\u0627\u062e\u062a\u0628\u0627\u0631", "source_dir": "\u0645\u062c\u0644\u062f \u0627\u0644\u0643\u0648\u062f \u0627\u0644\u0645\u062d\u0644\u064a",
    "api_contract": "\u0645\u0644\u0641 OpenAPI \u0645\u062d\u0644\u064a", "out": "\u0645\u0643\u0627\u0646 \u062d\u0641\u0638 \u0627\u0644\u0646\u062a\u0627\u0626\u062c",
    "rounds": "\u0623\u0642\u0635\u0649 \u0639\u062f\u062f \u0644\u0644\u062c\u0648\u0644\u0627\u062a", "requests": "\u0645\u0644\u0641 \u0637\u0644\u0628\u0627\u062a \u0623\u062f\u0648\u0627\u062a \u0627\u062e\u062a\u064a\u0627\u0631\u064a",
    "tool_profile": "\u0645\u062c\u0645\u0648\u0639\u0629 \u0623\u062f\u0648\u0627\u062a \u0627\u0644\u062a\u0646\u0641\u064a\u0630",
    "local_model": "\u0627\u0633\u062a\u062e\u062f\u0627\u0645 \u0646\u0645\u0648\u0630\u062c GGUF \u0645\u062d\u0644\u064a \u0645\u064f\u0639\u062f", "plan_only": "\u0625\u0639\u062f\u0627\u062f \u062e\u0637\u0629 \u062f\u0648\u0646 \u062a\u0634\u063a\u064a\u0644 \u0623\u062f\u0648\u0627\u062a",
    "resume": "\u0627\u0633\u062a\u0626\u0646\u0627\u0641 \u062a\u0646\u0641\u064a\u0630 \u0645\u062d\u0641\u0648\u0638 \u0645\u0637\u0627\u0628\u0642",
}
FIELD_HELP = {
    "target": "\u0623\u062f\u062e\u0644 \u0631\u0627\u0628\u0637 HTTP/HTTPS \u0648\u0627\u062d\u062f\u064b\u0627 \u0636\u0645\u0646 \u0645\u0644\u0641 \u0627\u0644\u0646\u0637\u0627\u0642. \u0644\u062a\u0634\u063a\u064a\u0644 \u0639\u062f\u0629 \u0631\u0648\u0627\u0628\u0637\u060c \u0627\u0633\u062a\u062e\u062f\u0645 --targets \u0645\u0646 CLI.",
    "scope": "\u0642\u0648\u0627\u0639\u062f \u0627\u0644\u0646\u0637\u0627\u0642 \u062a\u062d\u062f\u062f \u0645\u0627 \u064a\u0633\u0645\u062d \u0644\u0644\u0648\u0643\u0644\u0627\u0621 \u0628\u0641\u062d\u0635\u0647.",
    "authorized": "\u064a\u062c\u0628 \u0645\u0644\u0643\u064a\u0629 \u0627\u0644\u0647\u062f\u0641 \u0623\u0648 \u0648\u062c\u0648\u062f \u0625\u0630\u0646 \u0648\u0627\u0636\u062d \u0642\u0628\u0644 \u0627\u0644\u062a\u0646\u0641\u064a\u0630.",
    "traffic": "اختياري: اتركه فارغًا لفحص الرابط فقط. استخدمه فقط إذا كان لديك تصدير محفوظ مسبقًا: Burp XML أو ZAP HAR. يستخرج روابط فقط، ولا ينقل بيانات الدخول.",
    "workflow_manifest": "\u0645\u0644\u0641 JSON \u064a\u0635\u0641 \u0627\u0644\u0647\u0648\u064a\u0627\u062a \u0648\u062e\u0637\u0648\u0627\u062a \u0627\u0644\u0641\u062d\u0635 \u0627\u0644\u0645\u0635\u0631\u0651\u062d\u0629.",
    "api_contract": "\u0645\u0644\u0641 OpenAPI \u0645\u062d\u0644\u064a \u0644\u0645\u0631\u0627\u062c\u0639\u0629 \u0639\u0642\u062f API.",
    "source_dir": "\u0645\u062c\u0644\u062f \u0645\u0635\u062f\u0631 \u0645\u062d\u0644\u064a \u0644\u0645\u0631\u0627\u062c\u0639\u0629 \u0627\u0644\u0643\u0648\u062f.",
    "requests": "\u0628\u062f\u064a\u0644 \u0644\u0627\u062e\u062a\u064a\u0627\u0631 \u0627\u0644\u0645\u062d\u0648\u0651\u0644\u0627\u062a \u0641\u064a \u0627\u0644\u0642\u0627\u0626\u0645\u0629. \u0627\u062e\u062a\u0631 \u0637\u0631\u064a\u0642\u0629 \u0648\u0627\u062d\u062f\u0629; \u0648\u0627\u062a\u0631\u0643\u0647 \u0641\u0627\u0631\u063a\u064b\u0627 \u0644\u0644\u062e\u0637\u0629 \u0627\u0644\u0645\u062d\u0644\u064a\u0629.",
    "local_model": "\u064a\u062d\u0645\u0651\u0644 \u0646\u0645\u0648\u0630\u062c GGUF \u0645\u0646 \u062c\u0647\u0627\u0632\u0643 \u0641\u0642\u0637; \u0644\u0627 \u062a\u064f\u0633\u062a\u062e\u062f\u0645 \u062e\u062f\u0645\u0629 \u062a\u0634\u063a\u064a\u0644 \u062e\u0627\u0631\u062c\u064a. \u0627\u0644\u0645\u0644\u0627\u062d\u0638\u0627\u062a \u0627\u0644\u062d\u0631\u0629 \u062a\u062d\u062a\u0627\u062c \u0647\u0630\u0627 \u0627\u0644\u062e\u064a\u0627\u0631.",
    "plan_only": "\u064a\u0646\u0634\u0626 \u062e\u0637\u0629 \u0648\u0644\u0627 \u064a\u0637\u0644\u0642 \u0623\u062f\u0648\u0627\u062a \u0639\u0644\u0649 \u0627\u0644\u0647\u062f\u0641.",
    "resume": "\u064a\u062a\u0637\u0644\u0628 \u0646\u0641\u0633 \u0627\u0644\u0646\u0637\u0627\u0642 \u0648\u0627\u0644\u0645\u062f\u062e\u0644\u0627\u062a \u0648\u0639\u062f\u062f \u0627\u0644\u062c\u0648\u0644\u0627\u062a \u0627\u0644\u0633\u0627\u0628\u0642.",
    "tool_profile": "\u064a\u062d\u062f\u062f \u0623\u064a \u0645\u062c\u0645\u0648\u0639\u0629 \u0623\u062f\u0648\u0627\u062a \u064a\u0633\u0645\u062d \u0644\u0644\u0648\u0643\u0644\u0627\u0621 \u0628\u0627\u062e\u062a\u064a\u0627\u0631\u0647\u0627 \u062e\u0644\u0627\u0644 \u062c\u0645\u064a\u0639 \u0627\u0644\u062c\u0648\u0644\u0627\u062a.",
}
CHOICE_LABELS = {
    "tool_profile": {"all": "\u0643\u0644 \u0627\u0644\u0623\u062f\u0648\u0627\u062a \u0627\u0644\u0645\u062f\u0639\u0648\u0645\u0629",
                     "web": "\u0641\u062d\u0635 \u062a\u0637\u0628\u064a\u0642\u0627\u062a \u0627\u0644\u0648\u064a\u0628",
                     "discovery": "\u0627\u0643\u062a\u0634\u0627\u0641 \u0627\u0644\u0645\u0633\u0627\u0631\u0627\u062a \u0648\u0627\u0644\u0623\u0635\u0648\u0644",
                     "network": "\u0641\u062d\u0635 \u0627\u0644\u0634\u0628\u0643\u0629 \u0648 TLS"},
}
ADVANCED_TOOL_CHOICES = [
    ("nuclei", "\u0642\u0648\u0627\u0644\u0628 \u0643\u0634\u0641 \u0642\u0627\u0628\u0644\u0629 \u0644\u0644\u062a\u062d\u0642\u0642"),
    ("zap-baseline.py", "\u0641\u062d\u0635 \u062e\u0637 \u0627\u0644\u0623\u0633\u0627\u0633"),
    ("dalfox", "\u0645\u062f\u062e\u0644\u0627\u062a URL \u0630\u0627\u062a \u0645\u0639\u0627\u0645\u0644\u0627\u062a"),
    ("browser-xss", "\u062a\u062d\u0642\u0642 DOM \u0645\u062d\u062f\u0648\u062f"),
    ("browser-xss-auth", "\u0645\u062a\u0635\u0641\u062d \u0645\u0648\u062b\u0651\u0642\u061b \u064a\u062d\u062a\u0627\u062c \u0645\u0644\u0641 \u0647\u0648\u064a\u0629"),
    ("katana", "\u0632\u062d\u0641 \u0631\u0648\u0627\u0628\u0637 \u0636\u0645\u0646 \u0627\u0644\u0646\u0637\u0627\u0642"),
    ("ffuf", "\u0627\u0643\u062a\u0634\u0627\u0641 \u0645\u0633\u0627\u0631\u0627\u062a \u0628\u0642\u0627\u0626\u0645\u0629 \u0643\u0644\u0645\u0627\u062a \u0645\u062d\u0644\u064a\u0629"),
    ("nikto", "\u0645\u0631\u0627\u062c\u0639\u0629 \u0625\u0639\u062f\u0627\u062f\u0627\u062a \u0627\u0644\u0648\u064a\u0628"),
    ("nmap", "\u0645\u0644\u0641 \u0645\u0646\u0627\u0641\u0630 \u0645\u062d\u062f\u0648\u062f"),
    ("sslscan", "\u0625\u0639\u062f\u0627\u062f TLS \u0644\u0645\u0648\u0627\u0642\u0639 HTTPS"),
]


def discover_job_reports(output_path):
    """Read-only bounded discovery of text artifacts under the chosen job output."""
    root = Path(output_path).resolve()
    if root.is_file():
        return [root], False
    if not root.is_dir():
        raise FileNotFoundError("Job output is unavailable")
    pending, found, visited = [(root, 0)], [], 0
    truncated = False
    while pending:
        directory, depth = pending.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    visited += 1
                    if visited > 200:
                        return sorted(found), True
                    if entry.is_symlink():
                        continue
                    path = Path(entry.path).resolve()
                    try:
                        path.relative_to(root)
                    except ValueError:
                        continue
                    if entry.is_file(follow_symlinks=False) and path.suffix.lower() in {".json", ".md", ".txt"}:
                        found.append(path)
                    elif entry.is_dir(follow_symlinks=False):
                        if depth < 2 and len(pending) < 32:
                            pending.append((path, depth + 1))
                        else:
                            truncated = True
        except OSError:
            truncated = True
    return sorted(found), truncated


def launch_desktop(parser):
    try:
        import tkinter as tk
        from tkinter import ttk, filedialog, messagebox
        window = tk.Tk()
    except (ImportError, RuntimeError) as exc:
        print(f"Maher desktop requires Python Tk support and a graphical session ({type(exc).__name__}).", file=sys.stderr)
        return 2
    except Exception as exc:
        # Tcl/display diagnostics can contain local paths; keep the message short.
        print(f"Cannot open Maher desktop ({type(exc).__name__}); use the CLI in this session.", file=sys.stderr)
        return 2
    commands = next(action.choices for action in parser._actions if isinstance(action, argparse._SubParsersAction))
    commands = {name: command for name, command in commands.items() if name != "gui"}
    window.title("Maher \u2022 Local security workspace")
    window.geometry("1180x820")
    window.minsize(920, 650)
    window.configure(bg="#0b1220")
    style = ttk.Style(window)
    style.theme_use("clam")
    style.configure("TFrame", background="#0b1220")
    style.configure("TLabel", background="#0b1220", foreground="#dce7f5")
    style.configure("Title.TLabel", font=("Segoe UI", 27, "bold"), foreground="#53e0c0")
    style.configure("TButton", padding=(12, 8))
    style.configure("Primary.TButton", padding=(18, 10), font=("Segoe UI", 11, "bold"))
    style.configure("Primary.TButton", background="#167a70", foreground="#ffffff")
    style.map("Primary.TButton", background=[("active", "#209688"), ("disabled", "#46545e")])
    style.configure("TCheckbutton", background="#0b1220", foreground="#dce7f5")
    style.configure("TNotebook", background="#0b1220")
    style.configure("TNotebook.Tab", padding=(18, 9))
    events = queue.Queue(maxsize=4)
    state = {"running": False, "closing": False, "cancel": None, "job_output": None, "live_output": None}
    fields = []
    form_values = {}
    selected_tool_vars = {}
    operator_brief_box = None
    selected = tk.StringVar(value="agent-tools-run")
    model_path = tk.StringVar(value=os.environ.get("MAHER_GGUF_MODEL", ""))
    status = tk.StringVar(value="Ready \u2022 \u062c\u0627\u0647\u0632")

    header = ttk.Frame(window, padding=20)
    header.pack(fill="x")
    ttk.Label(header, text="Maher", style="Title.TLabel").pack(side="left")
    ttk.Label(header, text="LOCAL SECURITY WORKSPACE  /  \u0645\u0633\u0627\u062d\u0629 \u0639\u0645\u0644 \u0645\u062d\u0644\u064a\u0629").pack(side="left", padx=24)
    ttk.Label(header, textvariable=status).pack(side="right")
    body = ttk.Frame(window, padding=(20, 0, 20, 16))
    body.pack(fill="both", expand=True)
    navigation = ttk.Frame(body, padding=(0, 0, 20, 0))
    navigation.pack(side="left", fill="y")
    ttk.Label(navigation, text="OPERATIONS / \u0627\u0644\u0639\u0645\u0644\u064a\u0627\u062a").pack(anchor="w", pady=(0, 10))
    category = tk.StringVar(value=OPERATION_GROUPS["agent-tools-run"])
    category_picker = ttk.Combobox(navigation, textvariable=category,
                                   values=list(dict.fromkeys(OPERATION_GROUPS.values())),
                                   state="readonly", width=23)
    category_picker.pack(fill="x", pady=(0, 8))
    selector = tk.Listbox(navigation, bg="#121f33", fg="#dce7f5", selectbackground="#246b69",
                          relief="flat", width=24, height=19, exportselection=False)
    selector.pack(fill="y")
    names = list(commands)
    visible_names = []
    display_names = {name: OPERATION_LABELS.get(name, name.replace("-", " ").title()) for name in names}
    def refresh_operations(*_):
        visible_names[:] = [name for name in names if OPERATION_GROUPS.get(name, "Tools and setup") == category.get()]
        selector.delete(0, "end")
        for name in visible_names:
            selector.insert("end", display_names[name])
        if visible_names:
            preferred = "agent-tools-run" if "agent-tools-run" in visible_names else "auto-run"
            default_name = preferred if preferred in visible_names else visible_names[0]
            selector.selection_set(visible_names.index(default_name))
            show_form(default_name)
    category_picker.bind("<<ComboboxSelected>>", refresh_operations)
    main = ttk.Frame(body)
    main.pack(side="left", fill="both", expand=True)
    heading = ttk.Label(main, text="", font=("Segoe UI", 15, "bold"))
    heading.pack(anchor="w", pady=(0, 10))
    description = ttk.Label(main, text="", wraplength=850, justify="left")
    description.pack(anchor="w", pady=(0, 9))
    execute_button = ttk.Button(main, text="Run / تشغيل", style="Primary.TButton",
                                command=lambda: execute())
    execute_button.pack(anchor="e", pady=(0, 8))
    notebook = ttk.Notebook(main)
    notebook.pack(fill="both", expand=True)
    form_tab, output_tab, report_tab = (ttk.Frame(notebook, padding=12) for _ in range(3))
    notebook.add(form_tab, text="Options / \u0627\u0644\u062e\u064a\u0627\u0631\u0627\u062a")
    notebook.add(output_tab, text="Execution / \u0627\u0644\u062a\u0646\u0641\u064a\u0630")
    notebook.add(report_tab, text="Reports / \u0627\u0644\u062a\u0642\u0627\u0631\u064a\u0631")
    canvas = tk.Canvas(form_tab, bg="#0b1220", highlightthickness=0)
    scrollbar = ttk.Scrollbar(form_tab, orient="vertical", command=canvas.yview)
    canvas.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side="right", fill="y")
    canvas.pack(fill="both", expand=True)
    form = ttk.Frame(canvas)
    form_window = canvas.create_window((0, 0), window=form, anchor="nw")
    form.bind("<Configure>", lambda event: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.bind("<Configure>", lambda event: canvas.itemconfigure(form_window, width=event.width))

    def text_panel(parent):
        panel = tk.Text(parent, bg="#07101c", fg="#c9e5df", insertbackground="#53e0c0",
                        wrap="word", font=("Consolas", 10), relief="flat", state="disabled")
        scroll = ttk.Scrollbar(parent, command=panel.yview)
        panel.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        panel.pack(fill="both", expand=True)
        return panel

    output = text_panel(output_tab)
    report_buttons = ttk.Frame(report_tab)
    report_buttons.pack(fill="x", pady=(0, 8))
    report = text_panel(report_tab)
    report_files = {}
    chosen_report = tk.StringVar()
    report_note = tk.StringVar(value="Choose a job output or open a report file")

    def replace_text(panel, content):
        panel.configure(state="normal")
        panel.delete("1.0", "end")
        panel.insert("1.0", content)
        panel.configure(state="disabled")

    def flush_live_output():
        live = state.get("live_output")
        if live is None:
            return
        with live["lock"]:
            chunks = live["chunks"]
            live["chunks"] = []
            live["pending_chars"] = 0
            truncated = live["truncated"] and not live["truncation_noted"]
            if truncated:
                live["truncation_noted"] = True
        if not chunks and not truncated:
            return
        output.configure(state="normal")
        for stream_name, content in chunks:
            if stream_name not in live["seen"]:
                output.insert("end", f"\n[{stream_name}]\n")
                live["visible_chars"] += len(stream_name) + 4
                live["seen"].add(stream_name)
            output.insert("end", content)
            live["visible_chars"] += len(content)
        if truncated:
            note = "\n[Live preview reached its size limit; final captured output appears when the job ends.]\n"
            output.insert("end", note)
            live["visible_chars"] += len(note)
        excess = max(0, live["visible_chars"] - 200000)
        if excess:
            output.delete("1.0", f"1.0 + {excess} chars")
            live["visible_chars"] -= excess
        output.see("end")
        output.configure(state="disabled")

    def stream_output(live, stream_name, chunk):
        content = live["decoders"][stream_name].decode(chunk)
        if not content:
            return
        with live["lock"]:
            remaining = 200000 - live["pending_chars"]
            if remaining > 0:
                visible = content[:remaining]
                live["chunks"].append((stream_name, visible))
                live["pending_chars"] += len(visible)
            if len(content) > remaining:
                live["truncated"] = True

    def browse(variable, kind="file"):
        if kind == "directory":
            path = filedialog.askdirectory(parent=window, mustexist=False)
        elif kind == "save":
            path = filedialog.asksaveasfilename(parent=window)
        else:
            path = filedialog.askopenfilename(parent=window)
        if path:
            variable.set(path)

    def show_form(name):
        nonlocal operator_brief_box
        if state["running"]:
            return
        if fields:
            saved_values = {action.dest: variable.get() for action, flag, variable, required in fields}
            if selected_tool_vars:
                saved_values["_selected_tools"] = [tool for tool, variable in selected_tool_vars.items() if variable.get()]
            if operator_brief_box is not None:
                saved_values["_operator_brief"] = operator_brief_box.get("1.0", "end-1c")
            form_values[selected.get()] = saved_values
        selected.set(name)
        if name == "agent-tools-run":
            model_controls.pack_forget()
        elif not model_controls.winfo_manager():
            model_controls.pack(side="left")
        saved = form_values.get(name, {})
        heading.configure(text=display_names.get(name, name.replace("-", " ").title()))
        description.configure(text=OPERATION_DESCRIPTIONS.get(name, "Use the fields below to run this local CLI operation."))
        for child in form.winfo_children():
            child.destroy()
        fields.clear()
        selected_tool_vars.clear()
        operator_brief_box = None
        for action in commands[name]._actions:
            if isinstance(action, argparse._HelpAction):
                continue
            if name == "agent-tools-run" and action.dest in {
                "targets", "scope", "traffic", "tool", "operator_brief",
                "workflow_manifest", "requests", "local_model", "plan_only",
                "resume", "rounds", "tool_profile", "out",
            }:
                # The guided URL flow uses CLI defaults and needs no uploaded files.
                continue
            line = ttk.Frame(form, padding=(0, 6))
            line.pack(fill="x")
            flag = next((item for item in action.option_strings if item.startswith("--")), None)
            required = action.required or not action.option_strings or (name == "agent-tools-run" and action.dest == "target")
            is_toggle = isinstance(action, argparse._StoreTrueAction)
            label = FIELD_LABELS.get(action.dest, (flag or action.dest).replace("-", " ").replace("_", " ").title())
            ttk.Label(line, text="" if is_toggle else label + (" *" if required else ""),
                      width=29, wraplength=210).pack(side="left")
            if isinstance(action, argparse._StoreTrueAction):
                variable = tk.BooleanVar(value=saved.get(action.dest, bool(action.default)))
                ttk.Checkbutton(line, variable=variable, text=FIELD_LABELS.get(action.dest, action.help or action.dest)).pack(side="left")
            else:
                default = "" if action.default is None else str(action.default)
                labels = CHOICE_LABELS.get(action.dest, {})
                saved_value = saved.get(action.dest, default)
                variable = tk.StringVar(value=labels.get(saved_value, saved_value))
                if action.choices:
                    ttk.Combobox(line, textvariable=variable,
                                 values=[labels.get(str(item), str(item)) for item in action.choices],
                                 state="readonly", width=32).pack(side="left", fill="x", expand=True)
                else:
                    ttk.Entry(line, textvariable=variable).pack(side="left", fill="x", expand=True)
                    kind = None
                    if action.dest in {"source_dir", "result_dir", "watch"}:
                        kind = "directory"
                    elif action.dest == "out":
                        kind = "save" if name == "traffic-import" else "directory"
                    elif action.dest in {"db", "service_db", "research_db"}:
                        kind = "save"
                    elif action.dest in {"scope", "rules", "inventory", "traffic", "workflow_manifest",
                                         "api_contract", "path", "manifest", "targets", "requests"}:
                        kind = "file"
                    if kind:
                        button_text = "اختر ملفًا (اختياري)" if action.dest == "traffic" else "Browse"
                        ttk.Button(line, text=button_text, command=lambda value=variable, mode=kind: browse(value, mode)).pack(side="left", padx=4)
                help_text = FIELD_HELP.get(action.dest, action.help)
                if help_text:
                    ttk.Label(form, text=help_text, wraplength=700).pack(anchor="w", padx=29)
            fields.append((action, flag, variable, required))
        if name == "agent-tools-run":
            execute_button.configure(text="ابدأ فحص الرابط  /  Start URL scan")
            note = ttk.Label(form, text="أدخل الرابط وأكّد الإذن، ثم اضغط زر التنفيذ أعلاه. لا تحتاج إلى رفع ملفات؛ ستُشغّل المحوّلات المحلية المثبتة والمتاحة ضمن مضيف الرابط. فحص تسجيل الدخول يحتاج هوية وسير عمل مصرّحًا بهما مسبقًا.",
                             wraplength=730, justify="left")
            note.pack(anchor="w", pady=(3, 8))
        else:
            execute_button.configure(text="Run / تشغيل")
        if name == "agent-tools-run":
            from .tool_readiness import tool_readiness_snapshot

            readiness_text = tk.StringVar()
            readiness_box = ttk.LabelFrame(form, text="\u062a\u0648\u0641\u0631 \u0627\u0644\u0623\u062f\u0648\u0627\u062a \u0627\u0644\u0645\u062d\u0644\u064a\u0629", padding=8)
            readiness_box.pack(fill="x", pady=(14, 4))
            ttk.Label(readiness_box, textvariable=readiness_text, justify="left",
                      wraplength=730).pack(anchor="w", fill="x")

            def refresh_readiness():
                snapshot = tool_readiness_snapshot()
                lines = [f"\u0645\u062a\u0627\u062d {snapshot['available_count']} \u0645\u0646 {snapshot['total_count']} \u0645\u062d\u0648\u0651\u0644\u064b\u0627. \u0647\u0630\u0627 \u064a\u0641\u062d\u0635 PATH \u0648\u0627\u0644\u062a\u0628\u0639\u064a\u0627\u062a \u0641\u0642\u0637; \u0644\u0627 \u064a\u0634\u063a\u0651\u0644 \u0623\u062f\u0648\u0627\u062a."]
                for row in snapshot["tools"]:
                    if row["status"] == "available":
                        state_label = "\u0645\u062a\u0627\u062d"
                    elif row["status"] == "dependency_present_browser_unverified":
                        state_label = "Playwright \u0645\u062a\u0627\u062d\u061b \u0627\u0644\u0645\u062a\u0635\u0641\u062d \u063a\u064a\u0631 \u0645\u062a\u062d\u0642\u0642"
                    elif row["status"] == "workflow_only":
                        state_label = "\u0639\u0628\u0631 \u0645\u0644\u0641 \u0633\u064a\u0631 \u0639\u0645\u0644"
                    else:
                        state_label = "\u063a\u064a\u0631 \u0645\u062b\u0628\u062a"
                    lines.append(f"{row['tool']} \u2014 {state_label}")
                readiness_text.set("\n".join(lines))

            ttk.Button(readiness_box, text="\u062a\u062d\u062f\u064a\u062b \u062d\u0627\u0644\u0629 \u0627\u0644\u0623\u062f\u0648\u0627\u062a",
                       command=refresh_readiness).pack(anchor="e", pady=(6, 0))
            refresh_readiness()
        canvas.yview_moveto(0)

    def on_select(event):
        selection = selector.curselection()
        if selection:
            show_form(visible_names[selection[0]])
    selector.bind("<<ListboxSelect>>", on_select)

    def command():
        argv = [selected.get()]
        if selected.get() == "agent-tools-run" and not any(
            action.dest == "authorized" and variable.get()
            for action, _flag, variable, _required in fields
        ):
            raise ValueError("Confirm that you are authorized to assess this URL before execution.")
        for action, flag, variable, required in fields:
            value = variable.get()
            if isinstance(action, argparse._StoreTrueAction):
                if value:
                    argv.append(flag)
                continue
            if required and not value:
                raise ValueError(f"Required option: {flag or action.dest}")
            value = {label: key for key, label in CHOICE_LABELS.get(action.dest, {}).items()}.get(value, value)
            if value:
                argv.extend([flag, value] if flag else [value])
        if selected.get() == "agent-tools-run":
            for tool, variable in selected_tool_vars.items():
                if variable.get():
                    argv.extend(["--tool", tool])
            brief = operator_brief_box.get("1.0", "end-1c").strip() if operator_brief_box is not None else ""
            if brief:
                local_model_enabled = any(action.dest == "local_model" and variable.get()
                                          for action, flag, variable, required in fields)
                if not local_model_enabled:
                    raise ValueError("\u0641\u0639\u0651\u0644 \u0646\u0645\u0648\u0630\u062c GGUF \u0627\u0644\u0645\u062d\u0644\u064a \u0642\u0628\u0644 \u0643\u062a\u0627\u0628\u0629 \u062a\u0648\u062c\u064a\u0647 \u0644\u0644\u0648\u0643\u0644\u0627\u0621")
                argv.append("--operator-brief=" + brief)
        # Validate types/choices using the same parser that dispatches the CLI.
        try:
            parser.parse_args(argv)
        except SystemExit:
            raise ValueError("Invalid options; check numeric fields and required inputs") from None
        return [sys.executable, "-m", "maher_bounty.desktop_worker", *argv]

    def display_command(argv):
        return subprocess.list2cmdline(argv) if os.name == "nt" else shlex.join(argv)

    def preview():
        try:
            replace_text(output, display_command(command()))
            notebook.select(output_tab)
        except ValueError as exc:
            messagebox.showerror("Maher", str(exc), parent=window)

    def execute():
        if state["running"]:
            return
        try:
            argv = command()
        except ValueError as exc:
            messagebox.showerror("Maher", str(exc), parent=window)
            return
        environment = dict(os.environ)
        if model_path.get().strip():
            environment["MAHER_GGUF_MODEL"] = model_path.get().strip()
        else:
            environment.pop("MAHER_GGUF_MODEL", None)
        output_value = next((variable.get() for action, flag, variable, required in fields
                             if action.dest == "out"), None)
        if selected.get() == "agent-tools-run" and output_value is None:
            output_value = next((action.default for action in commands[selected.get()]._actions
                                 if action.dest == "out"), None)
        state["job_output"] = output_value
        state.update(running=True, cancel=threading.Event())
        selector.configure(state="disabled")
        execute_button.configure(state="disabled")
        status.set("Running \u2022 \u0642\u064a\u062f \u0627\u0644\u062a\u0646\u0641\u064a\u0630")
        progress.start(12)
        initial_output = display_command(argv) + "\n\nRunning. Live tool output will appear below.\n"
        replace_text(output, initial_output)
        live_state = {
            "lock": threading.Lock(), "chunks": [], "pending_chars": 0,
            "truncated": False, "truncation_noted": False, "seen": set(),
            "visible_chars": len(initial_output),
            "decoders": {name: codecs.getincrementaldecoder("utf-8")(errors="replace")
                         for name in ("stdout", "stderr")},
        }
        state["live_output"] = live_state
        notebook.select(output_tab)
        cancel_event = state["cancel"]

        def worker():
            try:
                completed = run(argv, capture_output=True, text=True, timeout=None,
                                env=environment, cancel_event=cancel_event, truncate_output=True,
                                on_output=lambda stream_name, chunk: stream_output(live_state, stream_name, chunk))
                label = "Finished" if completed.returncode == 0 else f"Failed (exit {completed.returncode})"
                if completed.output_truncated:
                    label += " (log capture truncated)"
                event = (label,
                         ("[Captured desktop log limited to first 8 MiB; job continued]\n" if completed.output_truncated else "")
                         + (completed.stdout or "") + "\n" + (completed.stderr or ""))
            except ProcessCancelled as exc:
                event = ("Cancelled \u2022 \u0645\u0644\u063a\u0649", (exc.output or "") + "\n" + (exc.stderr or ""))
            except OutputLimitExceeded as exc:
                event = ("Output limit reached", (exc.output or "") + "\n" + (exc.stderr or ""))
            except Exception as exc:
                event = ("Launch failed", type(exc).__name__ + ": " + str(exc))
            events.put(event)
        try:
            threading.Thread(target=worker, daemon=True).start()
        except RuntimeError:
            state["running"] = False
            progress.stop()
            status.set("Worker could not start")
            selector.configure(state="normal")
            execute_button.configure(state="normal")

    def cancel():
        if state["running"]:
            state["cancel"].set()
            status.set("Stopping process tree \u2022 \u062c\u0627\u0631\u064d \u0627\u0644\u0625\u064a\u0642\u0627\u0641")

    def read_report(path):
        try:
            with Path(path).open("rb") as stream:
                raw = stream.read(4 * 1024 * 1024 + 1)
            truncated = len(raw) > 4 * 1024 * 1024
            content = raw[:4 * 1024 * 1024].decode("utf-8-sig", errors="replace")
            replace_text(report, str(path) + ("\n[Preview truncated; original file unchanged]" if truncated else "") + "\n\n" + content)
            notebook.select(report_tab)
        except OSError as exc:
            messagebox.showerror("Maher", str(exc), parent=window)

    def open_report():
        path = filedialog.askopenfilename(parent=window, filetypes=[("Text reports", "*.json *.md *.txt"), ("All", "*")])
        if path:
            read_report(path)

    def refresh_reports():
        report_files.clear()
        if state["job_output"]:
            try:
                paths, partial = discover_job_reports(state["job_output"])
                root = Path(state["job_output"]).resolve()
                for path in paths:
                    label = path.name if root.is_file() else str(path.relative_to(root))
                    report_files[label] = path
                report_note.set(f"{len(paths)} artifact(s)" + (" | bounded/incomplete listing" if partial else ""))
            except (OSError, ValueError):
                report_note.set("Output folder unavailable; use Open report")
        else:
            report_note.set("No output path recorded for this command")
        report_picker.configure(values=list(report_files))
        chosen_report.set(next(iter(report_files), ""))

    def open_selected_report():
        path = report_files.get(chosen_report.get())
        if path is not None:
            read_report(path)
    ttk.Button(report_buttons, text="Open report / \u0641\u062a\u062d \u062a\u0642\u0631\u064a\u0631", command=open_report).pack(side="left")
    ttk.Button(report_buttons, text="Refresh job files", command=refresh_reports).pack(side="left", padx=4)
    report_picker = ttk.Combobox(report_buttons, textvariable=chosen_report, state="readonly", width=36)
    report_picker.pack(side="left", fill="x", expand=True, padx=4)
    ttk.Button(report_buttons, text="View", command=open_selected_report).pack(side="left")
    ttk.Label(report_tab, textvariable=report_note).pack(side="bottom", anchor="w")
    controls = ttk.Frame(main, padding=(0, 12, 0, 0))
    controls.pack(fill="x")
    model_controls = ttk.Frame(controls)
    model_controls.pack(side="left")
    ttk.Label(model_controls, text="Local GGUF (optional)").pack(side="left")
    ttk.Entry(model_controls, textvariable=model_path, width=28).pack(side="left", padx=7)
    ttk.Button(model_controls, text="Browse", command=lambda: browse(model_path)).pack(side="left")
    ttk.Button(controls, text="Preview", command=preview).pack(side="right", padx=4)
    ttk.Button(controls, text="Stop", command=cancel).pack(side="right", padx=4)
    progress = ttk.Progressbar(main, mode="indeterminate")
    progress.pack(fill="x", pady=(10, 0))

    def poll():
        flush_live_output()
        try:
            label, content = events.get_nowait()
        except queue.Empty:
            pass
        else:
            state["running"] = False
            progress.stop()
            status.set(label)
            selector.configure(state="normal")
            execute_button.configure(state="normal")
            # Bound the desktop preview independently of preserved tool artifacts.
            replace_text(output, ("[Output preview truncated]\n" if len(content) > 200000 else "") + content[-200000:])
            state["live_output"] = None
            refresh_reports()
            if state["closing"]:
                window.destroy()
                return
        window.after(150, poll)

    def close():
        if state["running"]:
            state["closing"] = True
            cancel()
        else:
            window.destroy()
    window.protocol("WM_DELETE_WINDOW", close)
    refresh_operations()
    window.after(150, poll)
    window.mainloop()
    return 0


def main():
    from .cli import build_parser
    return launch_desktop(build_parser())
