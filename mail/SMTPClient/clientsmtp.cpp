/*
 * SMTP client. It uses the SMTP protocol handler.
 * ------------------------------------
 * Developed: Rostislav Gashin (rost1993). The State University of Syktyvkar (Amplab).
 * Russia, Komi Republic, Syktyvkar - 21.07.2015.
*/

#include "clientsmtp.h"
#include "ui_clientsmtp.h"

// Вектор инициализации
uint8_t IV[16] = { 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5 };

// Переменная для временного хранения ключа
QString Password;

// Активируем режим "Открытый канал" - по умолчанию
int security = -1;

ClientSMTP::ClientSMTP(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::ClientSMTP)
{
    ui->setupUi(this);

    // Обработка нажатия кнопок
    connect(ui->pushButton_1, SIGNAL(clicked()), this, SLOT(slotModePasswordClient()));
    connect(ui->pushButton_2, SIGNAL(clicked()), this, SLOT(slotAutorizationToServer()));
    connect(ui->pushButton_3, SIGNAL(clicked()), this, SLOT(slotClearAllField()));
    connect(ui->pushButton_4, SIGNAL(clicked()), this, SLOT(slotNewFormSettings()));
}

ClientSMTP::~ClientSMTP()
{
    delete ui;
}

// Режим отображения поля для ввода пароля
void ClientSMTP::slotModePasswordClient(void)
{
    if(ui->pushButton_1->text() == "Отобразить") {
        ui->pushButton_1->setText("Скрыть");
        ui->lineEdit_2->setEchoMode(QLineEdit::Normal);
    }
    else {
        ui->pushButton_1->setText("Отобразить");
        ui->lineEdit_2->setEchoMode(QLineEdit::Password);
    }
}

// Попытка авторизации на сервере
void ClientSMTP::slotAutorizationToServer(void)
{
    if((ui->lineEdit_1->text() == "") || (ui->lineEdit_2->text() == "")) {
        QMessageBox::warning(this, QString::fromUtf8("Ошибка!"), QString::fromUtf8("Не заполнен Email или не введен пароль!"));
        return;
    }

    if(ui->lineEdit_3->text() == "") {
        QMessageBox::warning(this,QString::fromUtf8("Ошибка!"), QString::fromUtf8("Не введен Email получателя!"));
        return;
    }

    if((ui->lineEdit_4->text() == "") || (ui->textEdit_2->toPlainText() == "")) {
        QMessageBox::warning(this, QString::fromUtf8("Ошибка!"), QString::fromUtf8("Не введена тема сообщения или текст сообщения!\n"
                                                                                   "Нельзя отправлять пустые сообщения!"));
        return;
    }

    if(SenderPost.length() == 0) {
        SenderPost = ui->lineEdit_1->text();

        if(SenderPost.indexOf(QRegExp("@gmail.com")) > 0)
            SmtpServer = "smtp.gmail.com";

        if((SenderPost.indexOf(QRegExp("@yandex.ru")) > 0) || (SenderPost.indexOf(QRegExp("@ya.ru")) > 0))
            SmtpServer = "smtp.yandex.ru";

        if(SenderPost.indexOf(QRegExp("@mail.ru")) > 0)
            SmtpServer = "smtp.mail.ru";
    }

    SenderSubject = ui->lineEdit_4->text();
    SenderMessage = ui->textEdit_2->toPlainText();

    if(security != -1) {
        slotEncryptMessage();
    }

    RecepientPost = ui->lineEdit_3->text();

    slotSmtpServerCooperation();
    Password.clear();
}

// Взаимодействие с SMTP сервером
void ClientSMTP::slotSmtpServerCooperation(void)
{
    SmtpClient Smtp(SmtpServer, 465, SmtpClient::SslConnection);
    MimeText TextSender;
    MimeMessage MessageSender;

    Smtp.setUser(SenderPost);
    Smtp.setPassword(ui->lineEdit_2->text());

    if(!Smtp.connectToHost()) {
        ui->textEdit_1->setTextColor(QColor("red"));
        ui->textEdit_1->append("Подключение к SMTP серверу - Ошибка!\nВозможно проблемы с SSL!");
        return;
    }

    ui->textEdit_1->setTextColor(QColor("green"));
    ui->textEdit_1->append("Подключение к SMTP серверу - ОК!");

    if(!Smtp.login()) {
        ui->textEdit_1->setTextColor(QColor("red"));
        ui->textEdit_1->append("Авторизация на SMTP сервере - Ошибка!");
        return;
    }

    ui->textEdit_1->setTextColor(QColor("green"));
    ui->textEdit_1->append("Авторизация на SMTP сервере - ОК!");

    EmailAddress Sender(SenderPost, SenderPost);
    MessageSender.setSender(&Sender);

    EmailAddress To(RecepientPost, RecepientPost);
    MessageSender.addRecipient(&To);

    MessageSender.setSubject(SenderSubject);

    TextSender.setText(SenderMessage);
    MessageSender.addPart(&TextSender);

    if(!Smtp.sendMail(MessageSender)) {
        ui->textEdit_1->setTextColor(QColor("red"));
        ui->textEdit_1->append("Отправление сообщения - Ошибка!");
        return;
    }

    ui->textEdit_1->setTextColor(QColor("green"));
    ui->textEdit_1->append("Отправление сообщения - ОК!");

    Smtp.quit();

    ui->textEdit_1->setTextColor(QColor("green"));
    ui->textEdit_1->append("Отключение от SMTP сервера!\nGood by!");

    ui->lineEdit_4->clear();
    ui->textEdit_2->clear();

    SenderPost.clear();
    SenderMessage.clear();
    SenderSubject.clear();
    RecepientPost.clear();
    SmtpServer.clear();
}

// Чистим данные со всех полей
void ClientSMTP::slotClearAllField(void)
{
    ui->lineEdit_1->clear();
    ui->lineEdit_2->clear();
    ui->lineEdit_3->clear();
    ui->lineEdit_4->clear();
    ui->textEdit_2->clear();

    ui->textEdit_1->setTextColor(QColor("green"));
    ui->textEdit_1->append("Все поля было очищены!");
}

// Вызываем окно с настройками шифрования
void ClientSMTP::slotNewFormSettings(void)
{
    Settings *Form = new Settings(security);
    Form->setAttribute(Qt::WA_DeleteOnClose, true);
    Form->show();
}

// Принимаем данные со 2-й формы
void ClientSMTP::slotRecieveData(const QString Pass, int alg)
{
    Password.clear();
    Password = Pass;

    security = alg;
}

// Объединение всех типов структур для шифрования
union context {
    struct salsa_context salsa;
    struct rabbit_context rabbit;
    struct hc128_context hc128;
    struct sosemanuk_context sosemanuk;
    struct grain_context grain;
    struct mickey_context mickey;
    struct trivium_context trivium;
};

// Объявляем новые типы данных
typedef int (*set_t)(void *ctx, uint8_t *key, int keylen, uint8_t *iv, int ivlen);
typedef void (*crypt_t)(void *ctx, uint8_t *buf, uint32_t buflen, uint8_t *out);

// Объявление массивов функций
set_t set[] = { (set_t)salsa_set_key_and_iv,
                (set_t)rabbit_set_key_and_iv,
                (set_t)hc128_set_key_and_iv,
                (set_t)sosemanuk_set_key_and_iv,
                (set_t)grain_set_key_and_iv,
                (set_t)mickey_set_key_and_iv,
                (set_t)trivium_set_key_and_iv };

crypt_t crypt[] = { (crypt_t)salsa_crypt,
                    (crypt_t)rabbit_crypt,
                    (crypt_t)hc128_crypt,
                    (crypt_t)sosemanuk_crypt,
                    (crypt_t)grain_crypt,
                    (crypt_t)mickey_crypt,
                    (crypt_t)trivium_crypt };

// Задаем массив максимальных длин ключей для вектора инициализации
const int ivlen[7] = { 8, 8, 16, 16, 12, 10, 10 };

// Функция шифрования/расшифровывания
int
crypt_func(void *ctx, uint8_t *k, int keylen, uint8_t *buf, uint32_t buflen, uint8_t *out)
{
    if(set[security](ctx, k, keylen, IV, ivlen[security]))
        return -1;

    crypt[security](ctx, buf, buflen, out);

    return 0;
}

// Функция шифрования сообщения
void ClientSMTP::slotEncryptMessage(void)
{
    QByteArray ba;
    char *temp;
    uint8_t *buf, *out, k[32];
    uint32_t buflen;
    int keylen;
    union context context;

    buflen = SenderMessage.length();

    buf = new uint8_t[buflen];
    out = new uint8_t[buflen];

    // Получаем ключ
    keylen = Password.length();
    ba = Password.toLocal8Bit();
    temp = ba.data();
    memcpy(k, temp, keylen);

    // Заполняем в buf полученное сообщение
    ba = SenderMessage.toLocal8Bit();
    temp = ba.data();
    memcpy(buf, temp, buflen);

    switch (security) {
        case 0 : if(crypt_func(&(context.salsa), k, keylen, buf, buflen, out))
                    QMessageBox::warning(this, QString::fromUtf8("Ошибка!"), QString::fromUtf8("Ошибка при использовании алгоритма Salsa!"));
                 break;
        case 1 : if(crypt_func(&(context.rabbit), k, keylen, buf, buflen, out))
                    QMessageBox::warning(this, QString::fromUtf8("Ошибка!"), QString::fromUtf8("Ошибка при использовании алгоритма Rabbit!"));
                 break;
        case 2 : if(crypt_func(&(context.hc128), k, keylen, buf, buflen, out))
                    QMessageBox::warning(this, QString::fromUtf8("Ошибка!"), QString::fromUtf8("Ошибка при использовании алгоритма HC128!"));
                 break;
        case 3 : if(crypt_func(&(context.sosemanuk), k, keylen, buf, buflen, out))
                    QMessageBox::warning(this, QString::fromUtf8("Ошибка!"), QString::fromUtf8("Ошибка при использовании алгоритма Sosemanuk!"));
                 break;
        case 4 : if(crypt_func(&(context.grain), k, keylen, buf, buflen, out))
                    QMessageBox::warning(this, QString::fromUtf8("Ошибка!"), QString::fromUtf8("Ошибка при использовании алгоритма Grain!"));
                 break;
        case 5 : if(crypt_func(&(context.mickey), k, keylen, buf, buflen, out))
                    QMessageBox::warning(this, QString::fromUtf8("Ошибка!"), QString::fromUtf8("Ошибка при использовании алгоритма Mickey!"));
                 break;
        case 6 : if(crypt_func(&(context.trivium), k, keylen, buf, buflen, out))
                    QMessageBox::warning(this, QString::fromUtf8("Ошибка!"), QString::fromUtf8("Ошибка при использовании алгоритма Trivium!"));
                 break;
    }

    memcpy(temp, out, buflen);

    SenderMessage.clear();
    SenderMessage = QString::fromLocal8Bit(temp, buflen);

    delete [] buf;
    delete [] out;
}
