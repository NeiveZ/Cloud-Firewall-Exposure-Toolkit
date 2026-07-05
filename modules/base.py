#!/usr/bin/env python3
# modules/base.py — Base class for all CLVX modules

import time


class BaseModule:
    """
    Classe base de todo módulo CLVX (direct CLI module: NAME, options,
    _add_option, get_option/set_option, _validate, _finding).

    Toda subclasse deve definir:
      NAME, DESCRIPTION, REFERENCES (atributos de classe)
      _define_options(self)  -> chama self._add_option(...) pra cada opção
      run(self) -> list[dict]  -> roda o módulo e retorna findings
    """

    NAME        = "base/module"
    DESCRIPTION = "Base module"
    REFERENCES  = []

    def __init__(self):
        self.options = {}
        self._define_options()

    # ── Definição/gerenciamento de opções ───────────────────────────

    def _add_option(self, name: str, default: str, required: bool, description: str):
        self.options[name.upper()] = {
            "value": default,
            "required": required,
            "description": description,
        }

    def _define_options(self):
        raise NotImplementedError("Subclasse precisa implementar _define_options()")

    def set_option(self, name: str, value: str):
        key = name.upper()
        if key not in self.options:
            raise KeyError(f"Opção desconhecida: {name}")
        self.options[key]["value"] = value

    def get_option(self, name: str) -> str:
        key = name.upper()
        if key not in self.options:
            raise KeyError(f"Opção desconhecida: {name}")
        return self.options[key]["value"]

    def show_options(self):
        from utils.colors import Colors
        print(f"\n  {Colors.BOLD}{Colors.WHITE}Opções do módulo ({self.NAME}):{Colors.RESET}\n")
        if not self.options:
            print("    (nenhuma opção definida)\n")
            return
        name_w = max(len(n) for n in self.options) + 2
        for name, meta in self.options.items():
            req = f"{Colors.RED}sim{Colors.RESET}" if meta["required"] else f"{Colors.DARK_GRAY}não{Colors.RESET}"
            raw_val = meta["value"]
            val = raw_val if str(raw_val).strip() else f"{Colors.DARK_GRAY}<vazio>{Colors.RESET}"
            print(f"    {name.ljust(name_w)} {str(val):<28} obrigatório:{req}  "
                  f"{Colors.DARK_GRAY}{meta['description']}{Colors.RESET}")
        print()

    # ── Validação ────────────────────────────────────────────────────

    def _validate(self) -> bool:
        from utils.colors import print_status
        missing = [name for name, meta in self.options.items()
                   if meta["required"] and not str(meta["value"]).strip()]
        if missing:
            print_status(f"Opção(ões) obrigatória(s) faltando: {', '.join(missing)} "
                         f"(use: set {missing[0]} <valor>)", "error")
            return False
        return True

    # ── Findings (usados no relatório final) ────────────────────────

    def _finding(self, severity: str, check: str, target: str, detail: str = "") -> dict:
        return {
            "module": self.NAME,
            "severity": severity.upper(),
            "check": check,
            "target": target,
            "detail": detail,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ── Execução (implementado por cada módulo) ─────────────────────

    def run(self) -> list:
        raise NotImplementedError("Subclasse precisa implementar run()")
