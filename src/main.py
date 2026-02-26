# -*- coding: utf-8 -*-
import sys
import os
import subprocess
import platform
import json
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
import threading
import traceback
from typing import Dict, Optional, List
from urllib.parse import urlparse
from function import ManualGoogleSession

# Настройка пути к браузерам Playwright
# Корректно работает как из исходников, так и из упакованного PyInstaller-exe
# Определяем базовый каталог: в собранном onefile PyInstaller данные распаковываются
# во временную папку, путь к которой хранится в sys._MEIPASS. Используем его, чтобы
# найти встроенную папку ms-playwright.
if getattr(sys, 'frozen', False):
    # В onefile-режиме PyInstaller создаёт временную директорию _MEI***
    base_dir = getattr(sys, '_MEIPASS', os.path.dirname(sys.executable))
else:
    base_dir = os.path.dirname(os.path.abspath(__file__))

if platform.system() == "Darwin":  # macOS
    # Для macOS браузеры Playwright по умолчанию устанавливаются в кеш пользователя
    os.environ["PLAYWRIGHT_BROWSERS_PATH"] = os.path.expanduser("~/Library/Caches/ms-playwright")
else:  # Windows/Linux
    # Ищем каталог ms-playwright рядом с исполняемым файлом
    os.environ["PLAYWRIGHT_BROWSERS_PATH"] = os.path.join(base_dir, "ms-playwright")

WHOIS_REQUEST_DELAY = 1.0

def extract_domain_from_url(url: str) -> Optional[str]:
    """Извлекает чистый домен из строки URL/цитации."""
    if not url:
        return None
    try:
        # Обработка формата типа "example.com › contacts"
        if '›' in url:
            url = url.split('›')[0].strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        parsed = urlparse(url)
        domain = parsed.netloc
        if domain.startswith('www.'):
            domain = domain[4:]
        if '.' not in domain or len(domain) < 4:
            return None
        return domain.lower()
    except Exception:
        return None

def get_whois_data(domain: str) -> Dict[str, Optional[str]]:
    """Получает данные WHOIS для домена через whois.ru с использованием браузера."""
    whois_data = {
        'domain': domain,
        'citation_index': None,
        'alexa_rating': None,
        'registrar': None,
        'registration_date': None,
        'expiration_date': None,
        'days_until_expiration': None,
        'check_date': None,
        'external_links': None,
        'internal_links': None,
        'total_anchors': None,
        'outgoing_anchors': None,
        'domain_links': None,
        'page_title': None,
        'page_description': None,
        'whois_error': None
    }
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            whois_url = f'https://whois.ru/{domain}'
            page.goto(whois_url, wait_until='domcontentloaded')
            try:
                page.wait_for_selector('.list-group-item', timeout=10000)
            except:
                try:
                    button = page.query_selector('#whois_btn')
                    if button:
                        button.click()
                        page.wait_for_selector('.list-group-item', timeout=10000)
                except:
                    pass
            html_content = page.content()
            browser.close()

        soup = BeautifulSoup(html_content, 'html.parser')
        list_groups = soup.find_all('ul', class_='list-group')
        for ul in list_groups:
            items = ul.find_all('li', class_='list-group-item')
            for item in items:
                text = item.get_text().strip()
                strong = item.find('strong')
                if not strong:
                    continue
                value = strong.get_text().strip()
                if 'Индекс цитирования' in text:
                    whois_data['citation_index'] = value
                elif 'Рейтинг Alexa' in text:
                    whois_data['alexa_rating'] = value
                elif 'Регистратор домена' in text:
                    whois_data['registrar'] = value
                elif 'Дата регистрации' in text:
                    whois_data['registration_date'] = value
                elif 'Дата окончания' in text:
                    whois_data['expiration_date'] = value
                elif 'Закончится через' in text:
                    whois_data['days_until_expiration'] = value
                elif 'Дата проверки' in text:
                    whois_data['check_date'] = value
                elif 'Внешние ссылки домена' in text:
                    whois_data['external_links'] = value
                elif 'Внутренние ссылки' in text:
                    whois_data['internal_links'] = value
                elif 'Кол-во найденных анкоров' in text:
                    whois_data['total_anchors'] = value
                elif 'Кол-во исходящих анкоров' in text:
                    whois_data['outgoing_anchors'] = value
                elif 'Кол-во ссылок на домене' in text:
                    whois_data['domain_links'] = value
                elif 'Title страницы' in text:
                    whois_data['page_title'] = value
                elif 'Description страницы' in text:
                    whois_data['page_description'] = value

        time.sleep(WHOIS_REQUEST_DELAY)
    except Exception as e:
        whois_data['whois_error'] = f'Error: {str(e)}'
    return whois_data

class GoogleSearchWorker(QThread):
    """Worker thread для выполнения поиска в фоновом режиме"""
    progress_updated = pyqtSignal(str)
    results_ready = pyqtSignal(object)
    error_occurred = pyqtSignal(str)
    captcha_detected = pyqtSignal(int)

    def __init__(self, query, page_from, page_to, parse_all_pages, collect_contacts, results_per_page, profile_dir):
        super().__init__()
        self.query = query
        self.page_from = page_from
        self.page_to = page_to
        self.parse_all_pages = parse_all_pages
        self.collect_contacts = collect_contacts
        self.results_per_page = results_per_page
        self.profile_dir = profile_dir
        self.is_running = True
        self.captcha_resume_event = threading.Event()
        self.captcha_resume_event.set()

    def stop(self):
        self.is_running = False
        self.captcha_resume_event.set()

    def resume_after_captcha(self):
        self.captcha_resume_event.set()

    def emit_progress(self, message):
        if self.is_running:
            self.progress_updated.emit(message)

    def is_captcha_page(self, page):
        try:
            url = page.url.lower()
            return (
                'captcha' in url or
                '/sorry/' in url or
                'sorry/index' in url or
                page.locator('text=Я не робот').count() > 0 or
                page.locator('form[action*=\"sorry\"]').count() > 0
            )
        except Exception:
            return False

    def wait_for_captcha_resolution(self, page_number):
        self.emit_progress(
            f"Обнаружена капча на странице {page_number}. Решите капчу в открытом окне браузера "
            f"и нажмите кнопку 'Продолжить после капчи'."
        )
        self.captcha_resume_event.clear()
        self.captcha_detected.emit(page_number)
        while self.is_running and not self.captcha_resume_event.wait(0.5):
            pass
        return self.is_running

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
        """Основная функция поиска."""
        try:
            all_results = []
            with sync_playwright() as p:
                if not self.is_running:
                    return

                self.emit_progress("Запуск браузера...")
                context = p.chromium.launch_persistent_context(
                    user_data_dir=self.profile_dir,
                    headless=False,
                    args=[
                        '--disable-blink-features=AutomationControlled',
                        '--no-first-run',
                        '--no-default-browser-check',
                        '--start-maximized',
                    ],
                    locale='ru-RU',
                    no_viewport=True,
                )
                context.add_init_script("""
                    Object.defineProperty(navigator, 'webdriver', {
                        get: () => undefined,
                    });
                """)

                page = context.pages[0] if context.pages else context.new_page()
                contacts_page = context.new_page() if self.collect_contacts else None

                page_number = self.page_from
                start_value = max(0, (self.page_from - 1) * 10)
                first_url = f"https://www.google.com/search?q={self.query}&hl=ru&start={start_value}&filter=0"
                page.goto(first_url, wait_until='domcontentloaded', timeout=45000)

                while self.is_running:
                    if self.is_captcha_page(page):
                        if not self.wait_for_captcha_resolution(page_number):
                            break
                        page.wait_for_load_state('domcontentloaded', timeout=45000)
                        continue

                    target_page = "ALL" if self.parse_all_pages else str(self.page_to)
                    self.emit_progress(f"Обработка страницы {page_number} из {target_page}...")
                    time.sleep(random.uniform(2, 4))

                    html = page.content()
                    soup = BeautifulSoup(html, 'html.parser')

                    result_blocks = (
                        soup.select('div.MjjYud') or
                        soup.select('div.g') or
                        soup.select('div[data-ved]') or
                        soup.select('.tF2Cxc') or
                        soup.select('div.ZINbbc') or
                        soup.select('div.kCrYT')
                    )
                    self.emit_progress(f"Найдено блоков на странице {page_number}: {len(result_blocks)}")

                    if not result_blocks:
                        self.emit_progress("Блоки результатов не найдены")
                        if page_number == self.page_from:
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

                            a_tag = (
                                block.select_one('a[href^="http"]') or
                                block.select_one('a[href^="https"]') or
                                block.select_one('a.zReHs') or
                                block.select_one('h3 a') or
                                block.select_one('a[data-ved]')
                            )
                            h3_tag = (
                                block.select_one('h3') or
                                block.select_one('h3.LC20lb') or
                                block.select_one('.DKV0Md') or
                                block.select_one('h3.r') or
                                block.select_one('[role="heading"]')
                            )
                            cite_tag = (
                                block.select_one('cite') or
                                block.select_one('cite.qLRx3b') or
                                block.select_one('.tjvcx') or
                                block.select_one('.UdvAnf')
                            )
                            snippet_tag = (
                                block.select_one('div.VwiC3b') or
                                block.select_one('.s') or
                                block.select_one('span[data-ved]') or
                                block.select_one('.st') or
                                block.select_one('.X5LH0c')
                            )

                            if a_tag:
                                url_link = a_tag.get('href', '')
                            if h3_tag:
                                title = h3_tag.get_text(strip=True)
                            if cite_tag:
                                cite = cite_tag.get_text(strip=True)
                            if snippet_tag:
                                snippet = snippet_tag.get_text(strip=True)

                            if url_link and not url_link.startswith('http'):
                                continue

                            if title and url_link:
                                result_data = {
                                    'title': title,
                                    'url': url_link,
                                    'cite': cite,
                                    'snippet': snippet
                                }
                                if self.collect_contacts and contacts_page is not None:
                                    self.emit_progress(f"Собираем контакты с: {url_link}")
                                    contacts = self.fetch_page_contacts(url_link, contacts_page)
                                    result_data.update({
                                        'emails': ', '.join(contacts.get('emails', []))
                                    })
                                page_results.append(result_data)
                        except Exception as e:
                            self.emit_progress(f"Ошибка при обработке блока {i}: {e}")
                            continue

                    if not page_results:
                        self.emit_progress(f"Нет результатов на странице {page_number}, завершаем сбор")
                        break

                    all_results.extend(page_results)
                    self.emit_progress(f"Собрано {len(page_results)} результатов со страницы {page_number}")

                    if not self.parse_all_pages and page_number >= self.page_to:
                        break

                    next_btn = page.locator('a#pnnext')
                    if next_btn.count() == 0:
                        self.emit_progress("Следующая страница недоступна. Завершаем сбор.")
                        break

                    try:
                        next_btn.first.click(timeout=15000)
                        page.wait_for_load_state('domcontentloaded', timeout=45000)
                    except Exception as e:
                        self.emit_progress(f"Не удалось перейти на следующую страницу: {e}")
                        break

                    page_number += 1
                    time.sleep(random.uniform(2, 4))

                context.close()

            df = pd.DataFrame(all_results)
            if not df.empty:
                df = df.drop_duplicates(subset=['url'], keep='first')
            self.results_ready.emit(df)

        except Exception as e:
            self.error_occurred.emit(f"Критическая ошибка: {str(e)}\n{traceback.format_exc()}")
class WhoisWorker(QThread):
    """Фоновый поток для проверки доменов через WHOIS.ru"""
    progress_updated = pyqtSignal(str)
    whois_ready = pyqtSignal(object)
    error_occurred = pyqtSignal(str)

    def __init__(self, results_df: pd.DataFrame):
        super().__init__()
        self.results_df = results_df
        self.is_running = True

    def stop(self):
        self.is_running = False

    def emit_progress(self, message: str):
        if self.is_running:
            self.progress_updated.emit(message)

    def run(self):
        try:
            if self.results_df is None or self.results_df.empty:
                self.emit_progress("[WHOIS] Нет данных для обработки")
                self.whois_ready.emit(self.results_df if self.results_df is not None else pd.DataFrame())
                return

            # Сбор уникальных доменов
            unique_domains = set()
            for _, row in self.results_df.iterrows():
                if not self.is_running:
                    break
                domain = extract_domain_from_url(row.get('cite')) if 'cite' in row else None
                if not domain:
                    domain = extract_domain_from_url(row.get('url'))
                if domain:
                    unique_domains.add(domain)

            unique_domains = list(unique_domains)
            self.emit_progress(f"\n[WHOIS] Найдено уникальных доменов для проверки: {len(unique_domains)}")

            if not unique_domains:
                self.emit_progress("[WHOIS] Нет доменов для проверки")
                self.whois_ready.emit(self.results_df)
                return

            # Получение данных WHOIS
            whois_results: Dict[str, Dict[str, Optional[str]]] = {}
            for i, domain in enumerate(unique_domains, 1):
                if not self.is_running:
                    break
                self.emit_progress(f"[WHOIS] Обрабатываю домен {i}/{len(unique_domains)}: {domain}")
                data = get_whois_data(domain)
                whois_results[domain] = data
                if data.get('whois_error'):
                    self.emit_progress(f"[WHOIS] Ошибка для {domain}: {data['whois_error']}")
                else:
                    self.emit_progress(f"[WHOIS] Успешно получены данные для {domain}")

            # Обогащение исходного DataFrame
            enriched_rows: List[Dict] = []
            for _, row in self.results_df.iterrows():
                item = row.to_dict()
                domain = extract_domain_from_url(item.get('cite')) if item.get('cite') else None
                if not domain:
                    domain = extract_domain_from_url(item.get('url'))

                if domain and domain in whois_results:
                    info = whois_results[domain]
                    item.update({
                        'whois_domain': info.get('domain'),
                        'whois_citation_index': info.get('citation_index'),
                        'whois_alexa_rating': info.get('alexa_rating'),
                        'whois_registrar': info.get('registrar'),
                        'whois_registration_date': info.get('registration_date'),
                        'whois_expiration_date': info.get('expiration_date'),
                        'whois_days_until_expiration': info.get('days_until_expiration'),
                        'whois_check_date': info.get('check_date'),
                        'whois_external_links': info.get('external_links'),
                        'whois_internal_links': info.get('internal_links'),
                        'whois_total_anchors': info.get('total_anchors'),
                        'whois_outgoing_anchors': info.get('outgoing_anchors'),
                        'whois_domain_links': info.get('domain_links'),
                        'whois_page_title': info.get('page_title'),
                        'whois_page_description': info.get('page_description'),
                        'whois_error': info.get('whois_error')
                    })
                else:
                    item.update({
                        'whois_domain': None,
                        'whois_citation_index': None,
                        'whois_alexa_rating': None,
                        'whois_registrar': None,
                        'whois_registration_date': None,
                        'whois_expiration_date': None,
                        'whois_days_until_expiration': None,
                        'whois_check_date': None,
                        'whois_external_links': None,
                        'whois_internal_links': None,
                        'whois_total_anchors': None,
                        'whois_outgoing_anchors': None,
                        'whois_domain_links': None,
                        'whois_page_title': None,
                        'whois_page_description': None,
                        'whois_error': 'No domain found'
                    })
                enriched_rows.append(item)

            df_enriched = pd.DataFrame(enriched_rows)

            # Статистика
            successful = len([1 for _, r in df_enriched.iterrows() if r.get('whois_domain') and not r.get('whois_error')])
            failed = len([1 for _, r in df_enriched.iterrows() if r.get('whois_error') and r.get('whois_error') != 'No domain found'])
            no_domain = len([1 for _, r in df_enriched.iterrows() if r.get('whois_error') == 'No domain found'])

            self.emit_progress(f"[WHOIS] Успешно обработано доменов: {successful}")
            self.emit_progress(f"[WHOIS] Ошибок при обработке: {failed}")
            self.emit_progress(f"[WHOIS] Результатов без доменов: {no_domain}")

            self.whois_ready.emit(df_enriched)

        except Exception as e:
            self.error_occurred.emit(f"[WHOIS] Критическая ошибка: {str(e)}\n{traceback.format_exc()}")

class GoogleSearchGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.results_df = None
        self.whois_worker = None
        self.whois_checkbox = None
        self.report_button = None  # Кнопка для генерации отчета
        self.parse_button = None
        self.resume_button = None
        self.all_pages_checkbox = None
        self.page_from_spinbox = None
        self.page_to_spinbox = None
        self.manual_session = ManualGoogleSession(base_dir)
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

        # Страницы (от/до) или все
        search_layout.addWidget(QLabel("Страницы (от/до):"), 1, 0)
        self.page_from_spinbox = QSpinBox()
        self.page_from_spinbox.setRange(1, 500)
        self.page_from_spinbox.setValue(1)
        search_layout.addWidget(self.page_from_spinbox, 1, 1)

        self.page_to_spinbox = QSpinBox()
        self.page_to_spinbox.setRange(1, 500)
        self.page_to_spinbox.setValue(3)
        search_layout.addWidget(self.page_to_spinbox, 1, 2)

        self.all_pages_checkbox = QCheckBox("Парсить все страницы (пока есть 'Следующая')")
        search_layout.addWidget(self.all_pages_checkbox, 2, 0, 1, 3)

        # Ограничение результатов
        self.limit_results_checkbox = QCheckBox("Ограничить результаты на странице")
        search_layout.addWidget(self.limit_results_checkbox, 3, 0)
        self.results_per_page_spinbox = QSpinBox()
        self.results_per_page_spinbox.setRange(10, 100)
        self.results_per_page_spinbox.setValue(10)
        self.results_per_page_spinbox.setEnabled(False)
        search_layout.addWidget(self.results_per_page_spinbox, 3, 1)

        # Сбор контактов
        self.collect_contacts_checkbox = QCheckBox("Собирать email контакты")
        search_layout.addWidget(self.collect_contacts_checkbox, 4, 0)

        # Предлагать WHOIS проверку
        self.whois_checkbox = QCheckBox("Предлагать проверку доменов через WHOIS.ru после сбора")
        self.whois_checkbox.setChecked(True)
        search_layout.addWidget(self.whois_checkbox, 5, 0, 1, 2)

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
        self.search_button.clicked.connect(self.start_manual_search)
        buttons_layout.addWidget(self.search_button)

        self.parse_button = QPushButton("Начать парсинг")
        self.parse_button.clicked.connect(self.start_search)
        self.parse_button.setEnabled(False)
        buttons_layout.addWidget(self.parse_button)

        self.resume_button = QPushButton("Продолжить после капчи")
        self.resume_button.clicked.connect(self.resume_after_captcha)
        self.resume_button.setEnabled(False)
        buttons_layout.addWidget(self.resume_button)

        self.stop_button = QPushButton("Остановить")
        self.stop_button.clicked.connect(self.stop_search)
        self.stop_button.setEnabled(False)
        buttons_layout.addWidget(self.stop_button)

        self.save_button = QPushButton("Сохранить CSV/Excel")
        self.save_button.clicked.connect(self.save_results)
        self.save_button.setEnabled(False)
        buttons_layout.addWidget(self.save_button)

        # Кнопка для генерации HTML-отчета
        self.report_button = QPushButton("Сгенерировать HTML-отчет")
        self.report_button.clicked.connect(self.generate_html_report)
        self.report_button.setEnabled(False)
        buttons_layout.addWidget(self.report_button)

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
        self.all_pages_checkbox.toggled.connect(self.page_from_spinbox.setDisabled)
        self.all_pages_checkbox.toggled.connect(self.page_to_spinbox.setDisabled)

    def open_feedback_link(self):
        """Открывает ссылку для обратной связи в Telegram"""
        QDesktopServices.openUrl(QUrl("https://t.me/Userspoi"))

    def start_manual_search(self):
        """Открывает видимый браузер для ручной капчи и подготовки сессии."""
        query = self.query_input.text().strip()
        if not query:
            QMessageBox.warning(self, "Ошибка", "Введите поисковый запрос!")
            return

        try:
            self.manual_session.start_search(query)
            self.parse_button.setEnabled(True)
            self.resume_button.setEnabled(False)
            self.output_text.append("Открыт браузер с поисковым запросом.")
            self.output_text.append("Если есть капча - решите ее в браузере.")
            self.output_text.append("После появления результатов нажмите 'Начать парсинг'.")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось открыть браузер: {e}")

    def resume_after_captcha(self):
        if self.worker:
            self.worker.resume_after_captcha()
            self.resume_button.setEnabled(False)
            self.output_text.append("Продолжение после капчи запрошено.")

    def start_search(self):
        """Запуск поиска"""
        query = self.query_input.text().strip()
        if not query:
            QMessageBox.warning(self, "Ошибка", "Введите поисковый запрос!")
            return
        if not self.manual_session.is_active():
            QMessageBox.warning(self, "Поиск", "Сначала нажмите 'Начать поиск' и решите капчу в браузере.")
            return
        profile_dir = self.manual_session.profile_dir
        self.manual_session.stop()

        page_from = self.page_from_spinbox.value()
        page_to = self.page_to_spinbox.value()
        parse_all_pages = self.all_pages_checkbox.isChecked()
        if not parse_all_pages and page_to < page_from:
            QMessageBox.warning(self, "Ошибка", "Поле 'до' не может быть меньше поля 'от'.")
            return

        collect_contacts = self.collect_contacts_checkbox.isChecked()
        results_per_page = None
        if self.limit_results_checkbox.isChecked():
            results_per_page = self.results_per_page_spinbox.value()

        # Очистка вывода
        self.output_text.clear()
        self.output_text.append(f"Начинаем поиск по запросу: '{query}'")
        if parse_all_pages:
            self.output_text.append("Страницы: все доступные")
        else:
            self.output_text.append(f"Диапазон страниц: {page_from}-{page_to}")
        if results_per_page:
            self.output_text.append(f"Результатов на странице: {results_per_page}")
        if collect_contacts:
            self.output_text.append("Сбор контактов: включен")
        self.output_text.append("-" * 50)

        # Сброс WHOIS
        self.whois_worker = None

        # Настройка UI для поиска
        self.search_button.setEnabled(False)
        self.parse_button.setEnabled(False)
        self.resume_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.save_button.setEnabled(False)
        self.report_button.setEnabled(False)  # Отключаем кнопку отчета
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Неопределенный прогресс

        # Создание и запуск worker'а
        self.worker = GoogleSearchWorker(
            query,
            page_from,
            page_to,
            parse_all_pages,
            collect_contacts,
            results_per_page,
            profile_dir,
        )
        self.worker.progress_updated.connect(self.update_progress)
        self.worker.captcha_detected.connect(self.on_captcha_detected)
        self.worker.results_ready.connect(self.on_results_ready)
        self.worker.error_occurred.connect(self.on_error)
        self.worker.finished.connect(self.on_search_finished)
        self.worker.start()

    def stop_search(self):
        """Остановка поиска"""
        self.resume_button.setEnabled(False)
        if self.worker:
            self.worker.stop()
            self.worker.quit()
            self.worker.wait()
            self.output_text.append("Поиск остановлен пользователем")

        if self.whois_worker:
            self.whois_worker.stop()
            self.whois_worker.quit()
            self.whois_worker.wait()
            self.output_text.append("WHOIS-проверка остановлена пользователем")

    def update_progress(self, message):
        """Обновление прогресса"""
        self.output_text.append(message)
        self.output_text.moveCursor(self.output_text.textCursor().End)

    def on_captcha_detected(self, page_number):
        self.resume_button.setEnabled(True)
        self.output_text.append(
            f"Капча на странице {page_number}: "
            f"решите ее в браузере и нажмите 'Продолжить после капчи'."
        )

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
            self.report_button.setEnabled(True)  # Активируем кнопку отчета
        else:
            self.output_text.append("Результаты не найдены")

        # Предложение WHOIS проверки как в Yandex-скрипте
        if self.results_df is not None and not self.results_df.empty and self.whois_checkbox.isChecked():
            self.output_text.append("\n" + "=" * 60)
            self.output_text.append("ОСНОВНОЙ ПАРСИНГ ЗАВЕРШЕН")
            self.output_text.append("=" * 60)
            reply = QMessageBox.question(
                self,
                "WHOIS",
                "Хотите проверить домены через WHOIS.ru?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes
            )
            if reply == QMessageBox.Yes:
                self.output_text.append("\n[WHOIS] Начинаю проверку доменов...")
                self.start_whois_check()
            else:
                self.output_text.append("[WHOIS] Проверка доменов пропущена.")

    def start_whois_check(self):
        if self.results_df is None or self.results_df.empty:
            QMessageBox.warning(self, "WHOIS", "Нет данных для WHOIS-проверки")
            return

        # Настройка UI
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.search_button.setEnabled(False)
        self.parse_button.setEnabled(False)
        self.resume_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.save_button.setEnabled(False)
        self.report_button.setEnabled(False)  # Отключаем на время WHOIS

        # Запуск WhoisWorker
        self.whois_worker = WhoisWorker(self.results_df)
        self.whois_worker.progress_updated.connect(self.update_progress)
        self.whois_worker.whois_ready.connect(self.on_whois_ready)
        self.whois_worker.error_occurred.connect(self.on_error)
        self.whois_worker.finished.connect(self.on_whois_finished)
        self.whois_worker.start()

    def on_whois_ready(self, df_enriched: pd.DataFrame):
        # Обновляем текущий DataFrame на обогащённый
        self.results_df = df_enriched
        self.output_text.append("\n[WHOIS] Обогащенные данные получены. Можете сохранить результаты.")
        self.save_button.setEnabled(True)
        self.report_button.setEnabled(True)  # Активируем кнопку отчета после WHOIS

    def on_whois_finished(self):
        self.progress_bar.setVisible(False)
        self.search_button.setEnabled(True)
        self.parse_button.setEnabled(self.manual_session.is_active())
        self.resume_button.setEnabled(False)

    def on_error(self, error_message):
        """Обработка ошибок"""
        self.output_text.append(f"ОШИБКА: {error_message}")
        QMessageBox.critical(self, "Ошибка", error_message)

    def on_search_finished(self):
        """Завершение поиска"""
        self.search_button.setEnabled(True)
        self.parse_button.setEnabled(self.manual_session.is_active())
        self.resume_button.setEnabled(False)
        self.stop_button.setEnabled(False)
        self.progress_bar.setVisible(False)
        # Если WHOIS уже запущен — UI останется в неопределённом прогрессе, не меняем

    def closeEvent(self, event):
        """Гарантированно закрывает ручную сессию браузера."""
        try:
            self.manual_session.stop()
        finally:
            super().closeEvent(event)

    def save_results(self):
        """Сохранение результатов"""
        if self.results_df is None or self.results_df.empty:
            QMessageBox.warning(self, "Ошибка", "Нет данных для сохранения!")
            return

        query = self.query_input.text().strip()
        default_filename = f"google_results_{query.replace(' ', '_')}.csv"
        dialog = QFileDialog(self, "Сохранить результаты")
        dialog.setAcceptMode(QFileDialog.AcceptSave)
        dialog.setNameFilter("CSV files (*.csv);;Excel files (*.xlsx);;All files (*.*)")
        dialog.selectFile(default_filename)
        dialog.setOption(QFileDialog.DontUseNativeDialog, True)

        filename = ""
        if dialog.exec_():
            selected = dialog.selectedFiles()
            if selected:
                filename = selected[0]

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

    def generate_html_report(self):
        """Генерирует интерактивный HTML-отчет с фильтрами и кнопкой экспорта."""
        if self.results_df is None or self.results_df.empty:
            QMessageBox.warning(self, "Ошибка", "Нет данных для генерации отчета!")
            return

        # Создаем копию DataFrame, чтобы не модифицировать оригинал
        df_report = self.results_df.copy()

        # Очищаем имена столбцов для HTML (убираем точки и пробелы)
        df_report.columns = [col.replace('.', '_').replace(' ', '_') for col in df_report.columns]

        # Генерируем HTML-таблицу с помощью pandas
        html_table = df_report.to_html(
            table_id='dataTable',
            classes='display compact cell-border stripe hover order-column',
            escape=False,
            index=False
        )

        # Шаблон HTML с подключением DataTables и кнопкой экспорта (без кнопки печати)
        html_template = f"""
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Отчет по поиску: {self.query_input.text()}</title>

    <!-- DataTables CSS -->
    <link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/v/dt/jq-3.7.0/jszip-3.10.1/dt-2.0.3/af-2.7.0/b-3.0.1/b-colvis-3.0.1/b-html5-3.0.1/b-print-3.0.1/cr-2.0.0/date-1.5.2/fc-5.0.0/fh-4.0.1/kt-2.12.1/r-3.0.1/rg-1.5.0/rr-1.5.0/sc-2.4.1/sb-1.7.0/sp-2.3.0/sl-2.0.0/sr-1.4.1/datatables.min.css"/>

    <!-- jQuery (обязателен для DataTables) -->
    <script type="text/javascript" src="https://code.jquery.com/jquery-3.7.1.min.js"></script>

    <!-- DataTables JS -->
    <script type="text/javascript" src="https://cdn.datatables.net/v/dt/jq-3.7.0/jszip-3.10.1/dt-2.0.3/af-2.7.0/b-3.0.1/b-colvis-3.0.1/b-html5-3.0.1/b-print-3.0.1/cr-2.0.0/date-1.5.2/fc-5.0.0/fh-4.0.1/kt-2.12.1/r-3.0.1/rg-1.5.0/rr-1.5.0/sc-2.4.1/sb-1.7.0/sp-2.3.0/sl-2.0.0/sr-1.4.1/datatables.min.js"></script>

    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            text-align: center;
            margin-bottom: 20px;
        }}
        #exportButtons {{
            margin-bottom: 15px;
            text-align: center;
        }}
        .dt-buttons {{
            display: inline-block;
        }}
        .dt-button {{
            background-color: #007bff !important;
            color: white !important;
            border: none !important;
            padding: 8px 16px !important;
            margin: 5px !important;
            border-radius: 4px !important;
            cursor: pointer !important;
        }}
        .dt-button:hover {{
            background-color: #0056b3 !important;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Отчет по поиску: {self.query_input.text()}</h1>

        <div id="exportButtons">
            <!-- Кнопки экспорта будут сгенерированы автоматически DataTables -->
        </div>

        {html_table}

    </div>

    <script>
        $(document).ready(function() {{
            $('#dataTable').DataTable({{
                "language": {{
                    "url": "https://cdn.datatables.net/plug-ins/2.0.3/i18n/ru.json"
                }},
                "pageLength": 25,
                "dom": 'Bfrtip',
                "buttons": [
                    {{
                        "extend": 'csvHtml5',
                        "text": 'Скачать CSV',
                        "className": 'dt-button',
                        "charset": 'utf-8',
                        "bom": true,
                        "filename": 'report_{self.query_input.text().replace(' ', '_')}'
                    }},
                    {{
                        "extend": 'excelHtml5',
                        "text": 'Скачать Excel',
                        "className": 'dt-button',
                        "filename": 'report_{self.query_input.text().replace(' ', '_')}'
                    }},
                    // Кнопка печати удалена по требованию
                    {{
                        "extend": 'colvis',
                        "text": 'Показать/Скрыть столбцы',
                        "className": 'dt-button'
                    }}
                ],
                "initComplete": function() {{
                    // Добавляем фильтры под каждым столбцом
                    this.api().columns().every(function() {{
                        var column = this;
                        var header = $(column.header());
                        var title = header.text();
                        
                        // Создаем input для фильтрации
                        var input = $('<input type="text" placeholder="Фильтр ' + title + '" />')
                            .appendTo($(column.footer()).empty())
                            .on('keyup change clear', function() {{
                                if (column.search() !== this.value) {{
                                    column
                                        .search(this.value)
                                        .draw();
                                }}
                            }});
                    }});
                }}
            }});
        }});
    </script>
</body>
</html>
        """

        # Сохраняем HTML-файл во временную директорию
        query = self.query_input.text().strip()
        temp_filename = f"interactive_report_{query.replace(' ', '_')}.html"
        temp_path = os.path.join(os.getcwd(), temp_filename)  # Сохраняем в текущей директории

        try:
            with open(temp_path, 'w', encoding='utf-8') as f:
                f.write(html_template)
            self.output_text.append(f"Интерактивный HTML-отчет сгенерирован: {temp_path}")

            # Автоматически открываем файл в браузере
            QDesktopServices.openUrl(QUrl.fromLocalFile(temp_path))

            QMessageBox.information(self, "Успех", f"Отчет открыт в вашем браузере!")

        except Exception as e:
            error_msg = f"Ошибка при генерации или открытии HTML-отчета: {str(e)}"
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

