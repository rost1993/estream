#include "client.h"
#include "ui_client.h"

// Вектор инициализации
uint8_t IV[16] = { 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5 };

// Активируем режим "открытый канал" - по умолчанию
// Ставми значение flag = 0 - это значит что ключ еще не отправлен
int security = -1;
int flag = 0;

QString message, key;

Client::Client(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Client)
{
    ui->setupUi(this);

    connect(ui->pushButton_1, SIGNAL(clicked()), this, SLOT(slotConnectToServer()));
    connect(ui->pushButton_2, SIGNAL(clicked()), this, SLOT(slotDisconnectToServer()));
    connect(ui->pushButton_3, SIGNAL(clicked()), this, SLOT(slotSendToServer()));
    connect(ui->pushButton_4, SIGNAL(clicked()), this, SLOT(slotNewFormSettings()));
}

Client::~Client()
{
    delete ui;
}

// Подключение к серверу
void Client::slotConnectToServer()
{
    client = new QTcpSocket(this);

    client->connectToHost(ui->lineEdit_2->text(), ui->spinBox->value());

    nextBlockSize = 0;

    connect(client, SIGNAL(connected()), SLOT(slotConnected()));
    connect(client, SIGNAL(readyRead()), SLOT(slotReadServer()));
    connect(client, SIGNAL(error(QAbstractSocket::SocketError)), this, SLOT(slotError(QAbstractSocket::SocketError)));
    connect(ui->lineEdit_1, SIGNAL(returnPressed()), this, SLOT(slotReadServer()));
}

// Применение некоторых настроек при подключении к серверу
void Client::slotConnected()
{
    ui->textEdit->setTextColor(QColor("green"));
    ui->textEdit->append("Соединение с сервером установлено!");

    ui->pushButton_1->setEnabled(false);
    ui->pushButton_2->setEnabled(true);
    ui->pushButton_3->setEnabled(true);
    ui->pushButton_4->setEnabled(true);
    ui->lineEdit_1->setReadOnly(false);
}

// Отключение клиента от сервера
void Client::slotDisconnectToServer()
{
    client->disconnectFromHost();

    ui->textEdit->setTextColor(QColor("green"));
    ui->textEdit->append("Соединение с сервером закрыто!");

    ui->pushButton_1->setEnabled(true);
    ui->pushButton_2->setEnabled(false);
    ui->pushButton_3->setEnabled(false);
    ui->pushButton_4->setEnabled(false);
    ui->lineEdit_1->setReadOnly(true);
}

// Выводим по какой причине соединение с сервером не удалось
void Client::slotError(QAbstractSocket::SocketError err)
{
    QString msgError;

    msgError = "Error: " + (err == QAbstractSocket::HostNotFoundError ? "Сервер не найден!" :
                            err == QAbstractSocket::RemoteHostClosedError ? "Сервер закрыт, либо был выключен!" :
                            err == QAbstractSocket::ConnectionRefusedError ? "Соединение не было установлено!" :
                QString(client->errorString()));
    ui->textEdit->setTextColor(QColor("red"));
    ui->textEdit->append(msgError);
}

// Принимаем данные от сервера
void Client::slotReadServer()
{
    QDataStream in(client);

    for(;;) {

        if(!nextBlockSize) {
            if(client->bytesAvailable() < sizeof(quint16)) {
                break;
            }

            in >> nextBlockSize;
        }

        if(client->bytesAvailable() < nextBlockSize) {
            break;
        }

        QTime time;

        message.clear();
        in >> time >> message;

        if(security != -1)
            slotCrypt();

        ui->textEdit->setTextColor(QColor("black"));
        ui->textEdit->append(time.toString() + " Сообщение от сервера - " + message);

        nextBlockSize = 0;
        message.clear();
    }
}

// Отправляем сообщение серверу
void Client::slotSendToServer()
{
    QTime time;
    QByteArray arrBlock;
    QDataStream out(&arrBlock, QIODevice::WriteOnly);
    int index = -1;

    if(security != -1)
        slotSendKeyToServer();

    time = QTime::currentTime();
    message.clear();
    message = ui->lineEdit_1->text();

    ui->textEdit->setTextColor(QColor("black"));
    ui->textEdit->append(time.toString() + " Сообщение клиента - " + message);

    if(security != -1) {
        slotCrypt();
        index = security;
    }

    out << quint16(0) << index << time << message;
    out.device()->seek(0);
    out << quint16(arrBlock.size() - sizeof(quint16));

    client->write(arrBlock);
    ui->lineEdit_1->clear();
    message.clear();
}

// Отправляем ключ серверу
void Client::slotSendKeyToServer()
{
    QTime time;
    QString tempKey;
    QByteArray arrBlock;
    QDataStream out(&arrBlock, QIODevice::WriteOnly);
    char *temp;
    int i, keylen;

    keylen = key.length();
    arrBlock = key.toLocal8Bit();
    temp = arrBlock.data();

    for(i = 0; i < keylen; i++)
        temp[i] ^= 0xAB;

    tempKey = QString::fromLocal8Bit(temp, keylen);

    if(flag == 1)
        return;

    time = QTime::currentTime();
    out << quint16(0) << 7 << time << tempKey;
    out.device()->seek(0);
    out << quint16(arrBlock.size() - sizeof(quint16));

    client->write(arrBlock);
    flag = 1;
    tempKey.clear();
}

// Вызываем форму с настройками шифрования
void Client::slotNewFormSettings()
{
    Settings *form = new Settings(security);
    form->setAttribute(Qt::WA_DeleteOnClose, true);
    form->show();
}

// Принимаем данные со 2-й формы. Заполняем key
void Client::slotRecieveData(QString str, int alg)
{
    key.clear();

    security = alg;

    if(security != -1) {
        key = str;
        flag = 0;
    }
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

// Объявляем новые типы
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

void Client::slotCrypt()
{
    QByteArray ba;
    char *temp;
    uint8_t *buf, *out, k[32];
    uint32_t buflen;
    int keylen;
    union context context;

    buflen = message.length();

    buf = new uint8_t[buflen];
    out = new uint8_t[buflen];

    // Получаем ключ
    keylen = key.length();
    ba = key.toLocal8Bit();
    temp = ba.data();
    memcpy(k, temp, keylen);

    // Заполняем в buf полученное от клиента сообщение
    ba = message.toLocal8Bit();
    temp = ba.data();
    memcpy(buf, temp, buflen);

    switch (security) {
    case 0 : if(crypt_func(&(context.salsa), k, keylen, buf, buflen, out))
                QMessageBox::warning(this, "Error!", "Salsa algorithm error!");
             break;
    case 1 : if(crypt_func(&(context.rabbit), k, keylen, buf, buflen, out))
                QMessageBox::warning(this, "Error!", "Rabbit algorithm error!");
             break;
    case 2 : if(crypt_func(&(context.hc128), k, keylen, buf, buflen, out))
                QMessageBox::warning(this, "Error!", "HC128 algorithm error!");
             break;
    case 3 : if(crypt_func(&(context.sosemanuk), k, keylen, buf, buflen, out))
                QMessageBox::warning(this, "Error!", "Sosemanuk algorithm error!");
             break;
    case 4 : if(crypt_func(&(context.grain), k, keylen, buf, buflen, out))
                QMessageBox::warning(this, "Error!", "Grain algorithm error!");
             break;
    case 5 : if(crypt_func(&(context.mickey), k, keylen, buf, buflen, out))
                QMessageBox::warning(this, "Error!", "Mickey algorithm error!");
             break;
    case 6 : if(crypt_func(&(context.trivium), k, keylen, buf, buflen, out))
                QMessageBox::warning(this, "Error!", "Trivium algorithm error!");
             break;
    }

    memcpy(temp, out, buflen);

    message.clear();
    message = QString::fromLocal8Bit(temp, buflen);

    delete[] buf;
    delete[] out;
}
