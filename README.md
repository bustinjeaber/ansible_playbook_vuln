# ansible_playbook_vuln

![image](https://github.com/user-attachments/assets/be124bf2-47ad-4377-907b-faffa3472764)

## 1. Названо не менее двух жёстко заданных секретов (hard-coded secrets) в playbook и есть объяснение, почему такое хранение опасно

### 1.1 Найденные секреты и опасность хранения

Пароль пользователя appadmin:
```yaml
8: app_password: "Sup3rS3cr3tP@ssw0rd123"
```

Секретный токен, который генерируется с помощью "Secret" (используется openssl rand -hex 16):
```yaml
81: <p>Your secret token: {{ secret_token.stdout }}</p>
```

Не стоит хранить пароли в открытом виде, так как его можно легко скопировать, будь то сотрудник или злоумышлник. Более того, учитывая отсутствие https, его можно перехватить через mitm.

### 1.2 Предложение по исправлению

Можно хранить пароль в переменной окружения или воспользоваться Ansible Vault

## 2. Описано, какие риски связаны с отключением брандмауэра (ufw disable) и подавлением ошибок (ignore_errors: yes)? Предложите более надёжный способ обработки ошибок и управления доступом

### 2.1 Проблема
Проблема заключается в том, что благодаря ufw desable все порты становятся открытыми, а ignore_erros - скрывает все возможные сбои в работе.
```yaml
- name: Disable firewall to allow all traffic
  shell: ufw disable
  ignore_errors: yes
  tags: network
```

Из-за этого появляется риск доступа к уязвимым сервисам и взлому

### 2.2 Предложение по исправлению
```yaml
- name: Unable port 8080
  ufw:
    rule: allow
    port: 8080
    proto: tcp
- name: Turn on UFW
  ufw:
    state: enabled
    policy: deny
```

Также рекомендуется удалить ignore_errors, так как ни к чему хорошему он не приведет. Всегда нужно фиксировать состояние системы

## 3. Есть объяснение опасности отсутствия проверки контрольной суммы при скачивании архива (get_url без checksum). Приведен пример использования get_url с проверкой SHA256

### 3.1 Проблематика
В данном фрагменте происходит скачивания архива. В случае, если кто-то произведет подмену содержимого, например через mitm, то работа приложения может нарушиться (или вообще будет внедрен эксплоит).
```yaml
- name: Download application archive
  get_url:
    url: "{{ download_url }}"
    dest: "/tmp/app.tar.gz"
  tags: download
```

### 3.2 Предложения по исправлению
Проверять контрольную сумму

![image](https://github.com/user-attachments/assets/c6f9985c-450f-496c-9069-04e132a9dc14)

![image](https://github.com/user-attachments/assets/0128e0f9-e1cd-4707-a24e-d3dbdac2c719)

## 4. Описано, в чём заключается риск использования устаревшего образа nginx:1.18.0 и как лучше организовать обновление или сканирование образов

### 4.1 Проблематика
![image](https://github.com/user-attachments/assets/d9d25f22-593c-4ce9-a3bc-7d7b3fa10c8f)

В nginx:1.18.0 были найдены следующие уязвимости:
- CVE-2021-23017 : Уязвимость переполнения буфера в реализации HTTP/2 NGINX, позволяющая удаленным злоумышленникам выполнять произвольный код.
- CVE-2021-3618 : уязвимость в резолвере NGINX, позволяющая удаленным злоумышленникам вызвать отказ в обслуживании (DoS) или потенциально выполнить произвольный код.
- CVE-2020-11724 : уязвимость в обработке HTTP-запросов NGINX, позволяющая удаленным злоумышленникам вызвать отказ в обслуживании (DoS).

### 4.2 Предложение по решению
Всегда устанавливать новую release версию Nginx, чтобы минимизировать шанс наличия уязвимостей.

## 5. Есть объяснение, почему установка прав 0777 на рабочую директорию (work_dir) небезопасно, какие права рекомендуются и как их задать через Ansible

### 5.1 Проблематика

Права 0777 дают доступ любому пользователю изменять файлы в рабочей директории. Появляется риск xss атаки.

### 5.2 Решение проблемы

```yaml
- name: Rules for users
  file:
    path: "{{ work_dir }}"
    state: directory
    owner: "{{ app_user }}"
    group: "{{ app_user }}"
    mode: '0755'
- name: Files permissions
  file:
    path: "{{ work_dir }}"
    state: directory
    recurse: yes
    owner: "{{ app_user }}"
    group: "{{ app_user }}"
    mode: '0644'
```

## 6. Написан личный секретный токен их index.html и как можно избежать риска утечки токена в реальном проекте

### 6.1 Проблема
Ссылаясь на пункт 1, есть проблема вставки токена в html файл:

```yaml
- name: Deploy index.html with embedded token
  copy:
    dest: "{{ work_dir }}/index.html"
    content: |
      <!DOCTYPE html>
      <html>
      <head><title>Vulnerable Web App</title></head>
      <body>
        <h1>Welcome</h1>
        <p>Your secret token: {{ secret_token.stdout }}</p>
      </body>
      </html>
    owner: "{{ app_user }}"
    group: "{{ app_user }}"
    mode: '0644'
  tags: web
```

Соответсвенно, доступ к токену может получить любой пользователь, ведь запрос проходит без аутеннтификации

### 6.2 Предложение по исправлению
Предлагаю хранить токен в переменной окружения контейнера nginx..
```yaml
- name: Run Nginx container
  docker_container:
    name: "{{ container_name }}"
    image: "nginx:{{ image_version }}"
    state: started
    restart_policy: always
    ports:
      - "8080:80"
    volumes:
      - "{{ work_dir }}:/usr/share/nginx/html:ro"
    env:
      SECRET_TOKEN: "{{ secret_token.stdout }}"
  tags: docker
```
