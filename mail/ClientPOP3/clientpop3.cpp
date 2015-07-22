/*
 * POP3 client. It uses the POP3 protocol handler.
 * ------------------------------------
 * Developed: Rostislav Gashin (rost1993). The State University of Syktyvkar (Amplab).
 * Russia, Komi Republic, Syktyvkar - 21.07.2015.
*/

#include "clientpop3.h"
#include "ui_clientpop3.h"

// Вектор инициализации
uint8_t IV[16] = { 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5 };

// Переменная для временного хранения ключа
QString Password;
QString Message;

// Активируем режим "Открытый канал" - по умолчанию
int security = -1;

ClientPOP3::ClientPOP3(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::ClientPOP3)
{
    ui->setupUi(this);

    Client = new POP3();

    // Обрабатываем события нажатия кнопок
    connect(ui->pushButton_1, SIGNAL(clicked()), this, SLOT(slotModePasswordClient()));
    connect(ui->pushButton_2, SIGNAL(clicked()), this, SLOT(slotConnectToServer()));
    connect(ui->pushButton_3, SIGNAL(clicked()), this, SLOT(slotReceiveMessageList()));
    connect(ui->pushButton_4, SIGNAL(clicked()), this, SLOT(slotReceiveMessage()));
    connect(ui->pushButton_5, SIGNAL(clicked()), this, SLOT(slotNewFormSettings()));
}

ClientPOP3::~ClientPOP3()
{
    delete ui;
}

// Режим отображения поля для ввода пароля
void ClientPOP3::slotModePasswordClient(void)
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

// Подключение и атворизация на POP3 сервере
void ClientPOP3::slotConnectToServer(void)
{
    QString ClientPost;

    if(ui->pushButton_2->text() == "Отключиться") {
        slotDisconnectToServer();
        return;
    }

    if((ui->lineEdit_1->text() == "") || (ui->lineEdit_2->text() == "")) {
        QMessageBox::warning(this, QString::fromUtf8("Ошибка!"), QString::fromUtf8("Не заполнен Email или не введен пароль!"));
        return;
    }

    ClientPost = ui->lineEdit_1->text();

    if(ClientPost.indexOf(QRegExp("@gmail.com")) > 0)
        POP3Server = "pop.gmail.com";

    if((ClientPost.indexOf(QRegExp("@yandex.ru")) > 0) || (ClientPost.indexOf(QRegExp("@ya.ru")) > 0))
        POP3Server = "pop.yandex.ru";

    if(ClientPost.indexOf(QRegExp("@mail.ru")) > 0)
        POP3Server = "pop.mail.ru";

    Client->setInfoPOP3Server(POP3Server, 995, POP3::SslConnection);
    Client->setEmailAddres(ui->lineEdit_1->text(), ui->lineEdit_2->text());

    if(!Client->ConnectToHost()) {
        ui->textEdit_1->setTextColor(QColor("red"));
        ui->textEdit_1->append("Ошибка подключения к POP3 серверу!");
        return;
    }

    ui->textEdit_1->setTextColor(QColor("green"));
    ui->textEdit_1->append("Подключение к POP3 серверу - ОК!");

    if(!Client->AutorizationToHost()) {
        ui->textEdit_1->setTextColor(QColor("red"));
        ui->textEdit_1->append("Ошибка авторизации на POP3 сервере!");
        return;
    }

    ui->textEdit_1->setTextColor(QColor("green"));
    ui->textEdit_1->append("Авторизация на POP3 сервере - ОК!");

    ui->spinBox->setMaximum(Client->MaximumMessage);
    ui->spinBox->setValue(Client->MaximumMessage);

    ui->pushButton_2->setText("Отключиться");
    ui->lineEdit_2->clear();
    ui->label_5->setEnabled(true);
    ui->label_6->setEnabled(true);
    ui->pushButton_3->setEnabled(true);
    ui->pushButton_4->setEnabled(true);
    ui->pushButton_5->setEnabled(true);
    ui->spinBox->setEnabled(true);
}

// Разрыв сессии на PO3 сервере
void ClientPOP3::slotDisconnectToServer(void)
{
    if(!Client->QUIT()) {
        ui->textEdit_1->setTextColor(QColor("red"));
        ui->textEdit_1->append("Ошибка разрыва сессии на POP3 сервере!");
        return;
    }

    ui->textEdit_1->setTextColor(QColor("green"));
    ui->textEdit_1->append("Разрыв сессии на POP3 сервере - ОК!");

    ui->pushButton_2->setText("Подключиться");
    ui->lineEdit_2->clear();
    ui->label_5->setEnabled(false);
    ui->label_6->setEnabled(false);
    ui->pushButton_3->setEnabled(false);
    ui->pushButton_4->setEnabled(false);
    ui->pushButton_5->setEnabled(false);
    ui->spinBox->setEnabled(false);

    ui->textEdit_2->clear();
    Password.clear();
}

// Выгрузка всех сообщений с почтового ящика
void ClientPOP3::slotReceiveMessageList(void)
{
    int i;

    if(!Client->LIST()) {
        ui->textEdit_1->setTextColor(QColor("red"));
        ui->textEdit_1->append("Ошибка выгрузки списка сообщений с POP3 сервера!");
        return;
    }

    ui->textEdit_1->setTextColor(QColor("green"));
    ui->textEdit_1->append("Выгрузка списка сообщений с POP3 сервера - ОК!");

    ui->textEdit_2->clear();

    for(i = 0; i < Client->MessageList.size(); i++)
        ui->textEdit_2->append(Client->MessageList[i]);
}

// Выгрузка сообщения
void ClientPOP3::slotReceiveMessage(void)
{
    ClientMessage CM;

    if(!Client->RETR(ui->spinBox->value(), &CM)) {
        ui->textEdit_1->setTextColor(QColor("red"));
        ui->textEdit_1->append("Ошибка выгрузки сообщений с POP3 сервера!");
        return;
    }

    ui->textEdit_1->setTextColor(QColor("green"));
    ui->textEdit_1->append("Выгрузка сообщения с POP3 сервера - ОК!");

    Message = CM.Message;

    if(security != -1)
        slotDecryptMessage();

    ui->textEdit_2->clear();

    ui->textEdit_2->append("От кого: " + CM.Sender + "\n" + "Кому: " + CM.Recepient + "\n" + "Дата: " + CM.Date + "\n" + "Тема: " + CM.Subject);
    ui->textEdit_2->append("Текст письма:\n" + Message);

    Message.clear();
}

// Вызываем окно с настройками шифрования
void ClientPOP3::slotNewFormSettings(void)
{
    Settings *Form = new Settings(security);
    Form->setAttribute(Qt::WA_DeleteOnClose, true);
    Form->show();
}

// Принимаем данные со 2-й формы
void ClientPOP3::slotRecieveData(const QString Pass, int alg)
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
void ClientPOP3::slotDecryptMessage(void)
{
    QByteArray ba;
    char *temp;
    uint8_t *buf, *out, k[32];
    uint32_t buflen;
    int keylen;
    union context context;

    buflen = Message.length();

    buf = new uint8_t[buflen];
    out = new uint8_t[buflen];

    // Получаем ключ
    keylen = Password.length();
    ba = Password.toLocal8Bit();
    temp = ba.data();
    memcpy(k, temp, keylen);

    // Заполняем в buf полученное сообщение
    ba = Message.toLocal8Bit();
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

    Message.clear();
    Message = QString::fromLocal8Bit(temp, buflen);

    delete [] buf;
    delete [] out;
}

