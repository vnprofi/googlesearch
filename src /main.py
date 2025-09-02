import sys
import os
import subprocess
import platform
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout,
                             QWidget, QLabel, QLineEdit, QPushButton, QTextEdit,
                             QSpinBox, QCheckBox, QProgressBar, QFileDialog,
                             QMessageBox, QGroupBox, QGridLayout, QComboBox)
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QUrl
from PyQt5.QtGui import QFont, QIcon, QDesktopServices
from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup
import pandas as pd
import time
import random
import re
import traceback

# Настройка пути к браузерам Playwright
if platform.system() == "Darwin":  # macOS
    os.environ["PLAYWRIGHT_BROWSERS_PATH"] = os.path.expanduser("~/Library/Caches/ms-playwright")
else:  # Windows
    os.environ["PLAYWRIGHT_BROWSERS_PATH"] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ms-playwright")


class GoogleSearchWorker(QThread):
    """Worker thread для выполнения поиска в фоновом режиме"""
    progress_updated = pyqtSignal(str)
    results_ready = pyqtSignal(object)
    error_occurred = pyqtSignal(str)

    def __init__(self, query, max_pages, collect_contacts, results_per_page):
        super().__init__()
        self.query = query
        self.max_pages = max_pages
        self.collect_contacts = collect_contacts
        self.results_per_page = results_per_page
        self.is_running = True

    def stop(self):
        self.is_running = False

    def emit_progress(self, message):
        if self.is_running:
            self.progress_updated.emit(message)

    def extract_contacts(self, page_content, page=None):
        """Извлекает только email из HTML страницы"""
        soup = BeautifulSoup(page_content, 'html.parser')
        contacts = {'emails': []}

        # Извлекаем email с улучшенным паттерном
        email_pattern = r'\b[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?@[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}\b'
        emails = re.findall(email_pattern, page_content, re.IGNORECASE)
        # Собираем полные email адреса
        full_emails = []
        for match in re.finditer(email_pattern, page_content, re.IGNORECASE):
            full_emails.append(match.group(0))
        contacts['emails'] = list(set(full_emails))

        return contacts

    def fetch_page_contacts(self, url, page):
        """Получает контакты с одной страницы"""
        try:
            # Переходим на страницу
            page.goto(url, wait_until='domcontentloaded', timeout=20000)

            # Ждем дополнительной загрузки
            time.sleep(random.uniform(2, 4))

            # Пытаемся дождаться загрузки динамического контента
            try:
                page.wait_for_load_state('networkidle', timeout=10000)
            except:
                pass

            # Скроллим страницу чтобы загрузить ленивый контент
            try:
                page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                time.sleep(1)
                page.evaluate("window.scrollTo(0, 0)")
            except:
                pass

            # Получаем полный HTML после загрузки
            full_content = page.content()

            # Дополнительно ищем в специфичных элементах
            additional_content = ""

            # Ищем в footer, header, контактных секциях
            selectors = [
                'footer', 'header', '[class*="contact"]', '[class*="footer"]',
                '[class*="header"]', '[id*="contact"]', '[id*="footer"]',
                '[id*="header"]', '.contacts', '.contact-info', '.contact-us'
            ]

            for selector in selectors:
                try:
                    elements = page.locator(selector).all()
                    for element in elements:
                        try:
                            text = element.inner_html()
                            if text:
                                additional_content += text + " "
                        except:
                            continue
                except:
                    continue

            # Объединяем весь контент
            combined_content = full_content + " " + additional_content

            # Извлекаем контакты
            contacts = self.extract_contacts(combined_content, page)

            return contacts

        except Exception as e:
            self.emit_progress(f"Ошибка при обработке {url}: {e}")
            return {'emails': []}

    def run(self):
        """Основная функция поиска"""
        try:
            all_results = []

            with sync_playwright() as p:
                if not self.is_running:
                    return

                self.emit_progress("Запуск браузера...")
                browser = p.chromium.launch(
                    headless=True,
                    args=[
                        '--no-sandbox',
                        '--disable-blink-features=AutomationControlled',
                        '--disable-dev-shm-usage',
                        '--disable-gpu',
                        '--no-first-run',
                        '--no-default-browser-check',
                        '--disable-extensions',
                        '--disable-web-security',
                        '--disable-features=VizDisplayCompositor'
                    ]
                )

                context = browser.new_context(
                    locale='ru-RU',
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    viewport={'width': 1920, 'height': 1080},
                    extra_http_headers={
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                        'Accept-Language': 'ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3',
                        'Accept-Encoding': 'gzip, deflate',
                        'Connection': 'keep-alive',
                        'Upgrade-Insecure-Requests': '1'
                    }
                )

                # Улучшенное скрытие автоматизации
                context.add_init_script("""
                    Object.defineProperty(navigator, 'webdriver', {
                        get: () => undefined,
                    });

                    Object.defineProperty(navigator, 'plugins', {
                        get: () => [1, 2, 3, 4, 5],
                    });

                    Object.defineProperty(navigator, 'languages', {
                        get: () => ['ru-RU', 'ru', 'en-US', 'en'],
                    });

                    window.chrome = {
                        runtime: {}
                    };
                """)

                page = context.new_page()

                for page_num in range(self.max_pages):
                    if not self.is_running:
                        break

                    start = page_num * (self.results_per_page or 100)
                    url = f"https://www.google.com/search?q={self.query}&hl=ru&start={start}&num={self.results_per_page or 100}"

                    self.emit_progress(f"Обработка страницы {page_num + 1} из {self.max_pages}...")

                    try:
                        page.goto(url, wait_until='networkidle', timeout=30000)

                        if 'captcha' in page.url.lower() or page.locator('text=Я не робот').count() > 0:
                            self.emit_progress(f"Обнаружена капча на странице {page_num + 1}, пропускаем...")
                            time.sleep(random.uniform(15, 25))
                            continue

                        time.sleep(random.uniform(3, 7))

                        html = page.content()
                        soup = BeautifulSoup(html, 'html.parser')

                        # Расширенный поиск блоков результатов
                        result_blocks = (
                                soup.select('div.MjjYud') or
                                soup.select('div.g') or
                                soup.select('div[data-ved]') or
                                soup.select('.tF2Cxc') or
                                soup.select('div.ZINbbc') or
                                soup.select('div.kCrYT')
                        )

                        self.emit_progress(f"Найдено блоков на странице {page_num + 1}: {len(result_blocks)}")

                        if not result_blocks:
                            self.emit_progress("Блоки результатов не найдены")
                            if page_num == 0:  # Если первая страница пуста
                                self.emit_progress("Возможно, Google блокирует запросы")
                            break

                        page_results = []

                        if self.results_per_page:
                            result_blocks = result_blocks[:self.results_per_page]

                        for i, block in enumerate(result_blocks):
                            if not self.is_running:
                                break

                            try:
                                title = ''
                                url_link = ''
                                cite = ''
                                snippet = ''

                                # Расширенный поиск ссылок
                                a_tag = (block.select_one('a[href^="http"]') or
                                         block.select_one('a[href^="https"]') or
                                         block.select_one('a.zReHs') or
                                         block.select_one('h3 a') or
                                         block.select_one('a[data-ved]'))

                                # Расширенный поиск заголовков
                                h3_tag = (block.select_one('h3') or
                                          block.select_one('h3.LC20lb') or
                                          block.select_one('.DKV0Md') or
                                          block.select_one('h3.r') or
                                          block.select_one('[role="heading"]'))

                                # Расширенный поиск cite
                                cite_tag = (block.select_one('cite') or
                                            block.select_one('cite.qLRx3b') or
                                            block.select_one('.tjvcx') or
                                            block.select_one('.UdvAnf'))

                                # Расширенный поиск сниппета
                                snippet_tag = (block.select_one('div.VwiC3b') or
                                               block.select_one('.s') or
                                               block.select_one('span[data-ved]') or
                                               block.select_one('.st') or
                                               block.select_one('.X5LH0c'))

                                if a_tag:
                                    url_link = a_tag.get('href', '')
                                if h3_tag:
                                    title = h3_tag.get_text(strip=True)
                                if cite_tag:
                                    cite = cite_tag.get_text(strip=True)
                                if snippet_tag:
                                    snippet = snippet_tag.get_text(strip=True)

                                # Дополнительная проверка URL
                                if url_link and not url_link.startswith('http'):
                                    continue

                                if title and url_link:
                                    result_data = {
                                        'title': title,
                                        'url': url_link,
                                        'cite': cite,
                                        'snippet': snippet
                                    }

                                    if self.collect_contacts:
                                        self.emit_progress(f"Собираем контакты с: {url_link}")
                                        contacts = self.fetch_page_contacts(url_link, page)

                                        result_data.update({
                                            'emails': ', '.join(contacts.get('emails', []))
                                        })

                                    page_results.append(result_data)

                            except Exception as e:
                                self.emit_progress(f"Ошибка при обработке блока {i}: {e}")
                                continue

                        if not page_results:
                            self.emit_progress(f"Нет результатов на странице {page_num + 1}, завершаем сбор")
                            break

                        all_results.extend(page_results)
                        self.emit_progress(f"Собрано {len(page_results)} результатов со страницы {page_num + 1}")

                        # Увеличенная пауза между страницами
                        if self.is_running:
                            time.sleep(random.uniform(8, 15))

                    except Exception as e:
                        self.emit_progress(f"Ошибка на странице {page_num + 1}: {e}")
                        time.sleep(random.uniform(5, 10))
                        continue

                browser.close()

            # Удаляем дубликаты по URL
            df = pd.DataFrame(all_results)
            if not df.empty:
                df = df.drop_duplicates(subset=['url'], keep='first')

            self.results_ready.emit(df)

        except Exception as e:
            self.error_occurred.emit(f"Критическая ошибка: {str(e)}\n{traceback.format_exc()}")


class GoogleSearchGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.results_df = None
        self.init_ui()

    def init_ui(self):
        """Инициализация пользовательского интерфейса"""
        self.setWindowTitle("Google Search Tool v1.1")
        self.setGeometry(100, 100, 800, 650)

        # Основной виджет
        main_widget = QWidget()
        self.setCentralWidget(main_widget)

        # Основной layout
        main_layout = QVBoxLayout()
        main_widget.setLayout(main_layout)

        # Группа настроек поиска
        search_group = QGroupBox("Настройки поиска")
        search_layout = QGridLayout()

        # Поисковый запрос
        search_layout.addWidget(QLabel("Поисковый запрос:"), 0, 0)
        self.query_input = QLineEdit()
        self.query_input.setPlaceholderText("Введите поисковый запрос...")
        search_layout.addWidget(self.query_input, 0, 1, 1, 2)

        # Количество страниц
        search_layout.addWidget(QLabel("Количество страниц:"), 1, 0)
        self.pages_spinbox = QSpinBox()
        self.pages_spinbox.setRange(1, 50)
        self.pages_spinbox.setValue(3)
        search_layout.addWidget(self.pages_spinbox, 1, 1)

        # Ограничение результатов
        self.limit_results_checkbox = QCheckBox("Ограничить результаты на странице")
        search_layout.addWidget(self.limit_results_checkbox, 2, 0)

        self.results_per_page_spinbox = QSpinBox()
        self.results_per_page_spinbox.setRange(10, 100)
        self.results_per_page_spinbox.setValue(100)
        self.results_per_page_spinbox.setEnabled(False)
        search_layout.addWidget(self.results_per_page_spinbox, 2, 1)

        # Сбор контактов
        self.collect_contacts_checkbox = QCheckBox("Собирать email контакты")
        search_layout.addWidget(self.collect_contacts_checkbox, 3, 0)

        search_group.setLayout(search_layout)
        main_layout.addWidget(search_group)

        # Группа Readme
        info_group = QGroupBox("Ключевые особенности и рекомендации")
        info_layout = QVBoxLayout()
        readme_text = ("<ul style='margin-left: -20px;'>"
                       "<li><b>Производительность сбора:</b> Приложение обрабатывает до 100 результатов с каждой страницы поисковой выдачи Google.</li>"
                       "<li><b>Ограничения Google:</b> Поисковая система Google, как правило, ограничивает общее количество результатов примерно до 300 позиций (эквивалентно 3 страницам).</li>"
                       "<li><b>Сбор контактных данных:</b> Активация функции сбора email-адресов значительно увеличивает общее время выполнения задачи, так как требует последовательного посещения и анализа каждого найденного веб-сайта.</li>"
                       "</ul>")
        info_label = QLabel(readme_text)
        info_label.setWordWrap(True)
        info_layout.addWidget(info_label)
        info_group.setLayout(info_layout)
        main_layout.addWidget(info_group)


        # Кнопки управления
        buttons_layout = QHBoxLayout()

        self.search_button = QPushButton("Начать поиск")
        self.search_button.clicked.connect(self.start_search)
        buttons_layout.addWidget(self.search_button)

        self.stop_button = QPushButton("Остановить")
        self.stop_button.clicked.connect(self.stop_search)
        self.stop_button.setEnabled(False)
        buttons_layout.addWidget(self.stop_button)

        self.save_button = QPushButton("Сохранить результаты")
        self.save_button.clicked.connect(self.save_results)
        self.save_button.setEnabled(False)
        buttons_layout.addWidget(self.save_button)

        main_layout.addLayout(buttons_layout)

        # Прогресс бар
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        main_layout.addWidget(self.progress_bar)

        # Текстовое поле для вывода
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        main_layout.addWidget(self.output_text)

        # Кнопка для связи
        feedback_layout = QHBoxLayout()
        self.feedback_button = QPushButton("Предложить улучшение")
        self.feedback_button.setCursor(Qt.PointingHandCursor)
        self.feedback_button.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                font-weight: bold;
                border-radius: 5px;
                padding: 6px 12px;
                border: 1px solid #2980b9;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:pressed {
                background-color: #1f618d;
            }
        """)
        self.feedback_button.clicked.connect(self.open_feedback_link)
        feedback_layout.addStretch()
        feedback_layout.addWidget(self.feedback_button)
        main_layout.addLayout(feedback_layout)


        # Подключение сигналов
        self.limit_results_checkbox.toggled.connect(
            self.results_per_page_spinbox.setEnabled
        )

    def open_feedback_link(self):
        """Открывает ссылку для обратной связи в Telegram"""
        QDesktopServices.openUrl(QUrl("https://t.me/Userspoi"))

    def start_search(self):
        """Запуск поиска"""
        query = self.query_input.text().strip()
        if not query:
            QMessageBox.warning(self, "Ошибка", "Введите поисковый запрос!")
            return

        max_pages = self.pages_spinbox.value()
        collect_contacts = self.collect_contacts_checkbox.isChecked()
        results_per_page = None

        if self.limit_results_checkbox.isChecked():
            results_per_page = self.results_per_page_spinbox.value()

        # Очистка вывода
        self.output_text.clear()
        self.output_text.append(f"Начинаем поиск по запросу: '{query}'")
        self.output_text.append(f"Страниц: {max_pages}")
        if results_per_page:
            self.output_text.append(f"Результатов на странице: {results_per_page}")
        if collect_contacts:
            self.output_text.append("Сбор контактов: включен")
        self.output_text.append("-" * 50)

        # Настройка UI для поиска
        self.search_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.save_button.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Неопределенный прогресс

        # Создание и запуск worker'а
        self.worker = GoogleSearchWorker(query, max_pages, collect_contacts, results_per_page)
        self.worker.progress_updated.connect(self.update_progress)
        self.worker.results_ready.connect(self.on_results_ready)
        self.worker.error_occurred.connect(self.on_error)
        self.worker.finished.connect(self.on_search_finished)
        self.worker.start()

    def stop_search(self):
        """Остановка поиска"""
        if self.worker:
            self.worker.stop()
            self.worker.quit()
            self.worker.wait()
            self.output_text.append("Поиск остановлен пользователем")

    def update_progress(self, message):
        """Обновление прогресса"""
        self.output_text.append(message)
        self.output_text.moveCursor(self.output_text.textCursor().End)

    def on_results_ready(self, df):
        """Обработка готовых результатов"""
        self.results_df = df

        if not df.empty:
            self.output_text.append(f"\nПоиск завершен! Найдено {len(df)} уникальных результатов")

            if self.collect_contacts_checkbox.isChecked():
                total_emails = sum(1 for _, row in df.iterrows() if row.get('emails'))
                self.output_text.append(f"Найдено сайтов с email: {total_emails}")

                # Показываем примеры найденных контактов
                if total_emails > 0:
                    self.output_text.append("\nПримеры найденных email:")
                    count = 0
                    for _, row in df.iterrows():
                        if row.get('emails') and count < 3:
                            self.output_text.append(f"  {row['url']}: {row['emails'][:100]}...")
                            count += 1


            self.save_button.setEnabled(True)
        else:
            self.output_text.append("Результаты не найдены")

    def on_error(self, error_message):
        """Обработка ошибок"""
        self.output_text.append(f"ОШИБКА: {error_message}")
        QMessageBox.critical(self, "Ошибка", error_message)

    def on_search_finished(self):
        """Завершение поиска"""
        self.search_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setVisible(False)

    def save_results(self):
        """Сохранение результатов"""
        if self.results_df is None or self.results_df.empty:
            QMessageBox.warning(self, "Ошибка", "Нет данных для сохранения!")
            return

        query = self.query_input.text().strip()
        default_filename = f"google_results_{query.replace(' ', '_')}.csv"

        filename, _ = QFileDialog.getSaveFileName(
            self, "Сохранить результаты", default_filename,
            "CSV files (*.csv);;Excel files (*.xlsx);;All files (*.*)"
        )

        if filename:
            try:
                if filename.endswith('.xlsx'):
                    self.results_df.to_excel(filename, index=False)
                else:
                    self.results_df.to_csv(filename, index=False, encoding="utf-8-sig")

                self.output_text.append(f"Результаты сохранены в: {filename}")
                QMessageBox.information(self, "Успех", f"Результаты сохранены в:\n{filename}")
            except Exception as e:
                error_msg = f"Ошибка при сохранении: {str(e)}"
                self.output_text.append(error_msg)
                QMessageBox.critical(self, "Ошибка", error_msg)


def main():
    app = QApplication(sys.argv)

    # Установка стиля приложения
    app.setStyle('Fusion')

    # Создание и показ главного окна
    window = GoogleSearchGUI()
    window.show()

    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
