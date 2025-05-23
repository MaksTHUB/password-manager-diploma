
# Локальный менеджер паролей (дипломный проект)

Данный проект представляет собой защищённое ядро локального менеджера паролей.  
Он реализует основные функции безопасного хранения и управления паролями на уровне серверной логики.  
Система ориентирована на локальное использование, не требует подключения к интернету и может быть интегрирована в любое другое приложение (например, веб-интерфейс или мобильный клиент).

## Основные функции
- Регистрация и вход в систему
- Мастер-пароль для доступа к зашифрованным данным
- Шифрование паролей с использованием алгоритма Fernet
- Хранение старых ключей шифрования (MultiFernet)
- Экспорт и импорт записей с цифровой подписью (HMAC)
- Проверка устойчивости паролей
- Блокировка при множественных неверных попытках входа
- Двухфакторная аутентификация (2FA)

## Важная информация

❗ В случае потери мастер-пароля восстановление доступа к данным невозможно.  
Все записи остаются зашифрованными, и система не предусматривает механизмов восстановления.  
Проект не использует серверные или облачные компоненты — все данные хранятся локально.

## Безопасность

- Все чувствительные файлы (такие как `.env.enc`, `.keys.enc`, экспортированные данные) исключены из репозитория.
- Проект предназначен исключительно для локального использования в условиях ограниченного доверия к внешним средам.

## Запуск

После запуска необходимо пройти регистрацию, указав мастер-пароль.  
Система автоматически сгенерирует ключи шифрования и создаст все необходимые файлы для работы.
