from __future__ import annotations


class SignatureMatchingLayer:
    def __init__(self, *args, **kwargs) -> None:
        self.signatures = []

    def process(self, data):
        return {"packets": data.get("packets", [])}
