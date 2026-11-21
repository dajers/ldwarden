from __future__ import annotations

import unittest

from app.services.telegram_format import split_markdown, to_telegram_markdown


class TelegramFormatTests(unittest.TestCase):
    def test_heading_bold_and_bullets(self):
        result = to_telegram_markdown("# Отчёт\n\n**Важно**\n\n- пункт один\n- пункт два")
        self.assertIn("*Отчёт*", result)
        self.assertIn("*Важно*", result)
        self.assertIn("• пункт один", result)
        self.assertIn("• пункт два", result)

    def test_inline_code_and_link(self):
        result = to_telegram_markdown("Статус `success`, см. [CVE-2022-1](https://osv.dev/x)")
        self.assertIn("`success`", result)
        self.assertIn("[CVE\\-2022\\-1](https://osv.dev/x)", result)

    def test_table_becomes_lines(self):
        result = to_telegram_markdown("| Критичность | Находок |\n| --- | --- |\n| Критическая | 1 |")
        self.assertIn("• Критичность — Находок", result)
        self.assertIn("• Критическая — 1", result)
        self.assertNotIn("---", result)

    def test_special_characters_are_escaped(self):
        result = to_telegram_markdown("a_b, 1.2, (x), {y}, #tag, +1, 50%!")
        for chunk in ("a\\_b", "1\\.2", "\\(x\\)", "\\{y\\}", "\\#tag", "\\+1", "50%\\!"):
            self.assertIn(chunk, result)

    def test_code_block_kept(self):
        result = to_telegram_markdown("```\nval x = 1\n```")
        self.assertIn("```", result)
        self.assertIn("val x = 1", result)

    def test_chunks_do_not_exceed_size(self):
        text = "\n".join(f"строка {index}" for index in range(200))
        chunks = split_markdown(text, 400)
        self.assertGreater(len(chunks), 1)
        self.assertTrue(all(len(chunk) <= 400 for chunk in chunks))


if __name__ == "__main__":
    unittest.main()
