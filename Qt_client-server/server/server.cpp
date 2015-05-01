// Файл описания сервера

#include "server.h"
#include "ui_server.h"

// Вектор инициализации
uint8_t IV[16] = { 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5 };

// Переменная для хранения текста сообщения
QString message;

Server::Server(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Server)
{
    ui->setupUi(this);

    // Режим открытого канала
    security = -1;

    connect(ui->pushButton_1, SIGNAL(clicked()), this, SLOT(slotStartStopServer()));
}

Server::~Server()
{
    delete ui;
}

// Запуск/остановка сервера. Если сервер запущен, то ожидает подключений клиентов
void Server::slotStartStopServer()
{
    QHostAddress IP;

    server = new QTcpServer(this);

    IP = QHostAddress(ui->lineEdit_2->text());

    if(ui->pushButton_1->text() == "Старт") {

        if(!server->listen(IP, ui->spinBox->value())) {
            QMessageBox::warning(this, "Error!", "Error start server - " + server->errorString());
            server->close();
            ui->textEdit->setTextColor(QColor("red"));
            ui->textEdit->append("Сервер не запущен! Ошибка - " + server->errorString());
            return;
        }

        ui->pushButton_1->setText("Стоп");
        ui->textEdit->setTextColor(QColor("green"));
        ui->textEdit->append("Сервер запущен!");
        QMessageBox::information(this, "Information!", "Server is started!");

        nextBlockSize = 0;
        connect(server, SIGNAL(newConnection()), this, SLOT(slotConnectionClient()));
    }
    else {
        ui->pushButton_1->setText("Старт");
        server->close();
        ui->textEdit->setTextColor(QColor("green"));
        ui->textEdit->append("Сервер остановлен!");
        QMessageBox::information(this, "Information!", "Server is stopped!");
    }
}

// Подключаем нового клиента. Ожидаем прием данных от клиента, либо отключение, либо можно отправить клиенту сообщение
void Server::slotConnectionClient()
{
    client = server->nextPendingConnection();

    ui->textEdit->setTextColor(QColor("green"));
    ui->textEdit->append("Подключен новый клиент!");
    ui->pushButton_2->setEnabled(true);
    ui->lineEdit_1->setReadOnly(false);

    // Слоты обработки событий доступных клиенту
    connect(client, SIGNAL(disconnected()), this, SLOT(slotDisconnectionClient()));
    connect(client, SIGNAL(readyRead()), this, SLOT(slotReadClient()));
    connect(ui->pushButton_2, SIGNAL(clicked()), this, SLOT(slotSendToClient()));
}

// Отключение клиента
void Server::slotDisconnectionClient()
{
    QTcpSocket *client = (QTcpSocket *)sender();
    connect(client, SIGNAL(disconnected()), client, SLOT(deleteLater()));

    ui->textEdit->setTextColor(QColor("green"));
    ui->textEdit->append("Клиент отключился!");
    ui->pushButton_2->setEnabled(false);
    ui->lineEdit_1->setReadOnly(true);
    key.clear();
}

// Принимаем сообщение от клиента
void Server::slotReadClient()
{
    QTcpSocket *client = (QTcpSocket *)sender();
    QDataStream in(client);
    QByteArray arrBLock;
    char *temp;
    int i;

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
        int index;

        message.clear();

        in >> index >> time >> message;

        // Получаем ключ
        if(index == 7) {
            arrBLock = message.toLocal8Bit();
            temp = arrBLock.data();

            for(i = 0; i < message.length(); i++)
                temp[i] ^= 0xAB;

            key.clear();
            key = QString::fromLocal8Bit(temp, message.length());
            nextBlockSize = 0;
        }

        // Получаем зашифрованное сообщение
        if((index >= 0) && (index <= 6)) {
            security = index;
            slotCrypt();
        }

        if(index != 7) {
            ui->textEdit->setTextColor(QColor("black"));
            ui->textEdit->append(time.toString() + " Сообщение от клиента - " + message);
        }

        nextBlockSize = 0;
        message.clear();
    }
}

// Отправляем сообщение клиенту
void Server::slotSendToClient()
{
    QTime time;
    QByteArray arrBlock;
    QDataStream out(&arrBlock, QIODevice::WriteOnly);

    message.clear();
    message = ui->lineEdit_1->text();
    time = QTime::currentTime();
    ui->textEdit->setTextColor(QColor("black"));
    ui->textEdit->append(time.toString() + " Сообщение сервера - " + message);

    if(security != -1) {
        slotCrypt();
    }

    // Формируем сообщение
    out << quint16(0) << time << message;
    out.device()->seek(0);
    out << quint16(arrBlock.size() - sizeof(quint16));

    // Отправляем сообщение клиенту
    client->write(arrBlock);
    ui->lineEdit_1->clear();
    message.clear();
}

int
salsa(uint8_t *k, int keylen, uint8_t *buf, uint32_t buflen, uint8_t *out)
{
    struct salsa_context ctx;

    salsa_init(&ctx);

    if(salsa_set_key_and_iv(&ctx, k, keylen, IV, 8))
        return -1;

    salsa_encrypt(&ctx, buf, buflen, out);

    return 0;
}

int
rabbit(uint8_t *k, int keylen, uint8_t *buf, uint32_t buflen, uint8_t *out)
{
    struct rabbit_context ctx;

    rabbit_init(&ctx);

    if(rabbit_set_key_and_iv(&ctx, k, keylen, IV, 8))
        return -1;

    rabbit_encrypt(&ctx, buf, buflen, out);

    return 0;
}

int
hc128(uint8_t *k, int keylen, uint8_t *buf, uint32_t buflen, uint8_t *out)
{
    struct hc128_context ctx;

    hc128_init(&ctx);

    if(hc128_set_key_and_iv(&ctx, k, keylen, IV, 16))
        return -1;

    hc128_encrypt(&ctx, buf, buflen, out);

    return 0;
}

int
sosemanuk(uint8_t *k, int keylen, uint8_t *buf, uint32_t buflen, uint8_t *out)
{
    struct sosemanuk_context ctx;

    sosemanuk_init(&ctx);

    if(sosemanuk_set_key_and_iv(&ctx, k, keylen, IV, 16))
        return -1;

    sosemanuk_encrypt(&ctx, buf, buflen, out);

    return 0;
}

int
grain(uint8_t *k, int keylen, uint8_t *buf, uint32_t buflen, uint8_t *out)
{
    struct grain_context ctx;

    grain_init(&ctx);

    if(grain_set_key_and_iv(&ctx, k, keylen, IV, 12))
        return -1;

    grain_encrypt(&ctx, buf, buflen, out);

    return 0;
}

int
mickey(uint8_t *k, int keylen, uint8_t *buf, uint32_t buflen, uint8_t *out)
{
    struct mickey_context ctx;

    mickey_init(&ctx);

    if(mickey_set_key_and_iv(&ctx, k, keylen, IV, 10))
        return -1;

    mickey_encrypt(&ctx, buf, buflen, out);

    return 0;
}

int
trivium(uint8_t *k, int keylen, uint8_t *buf, uint32_t buflen, uint8_t *out)
{
    struct trivium_context ctx;

    trivium_init(&ctx);

    if(trivium_set_key_and_iv(&ctx, k, keylen, IV, 10))
        return -1;

    trivium_encrypt(&ctx, buf, buflen, out);

    return 0;
}

// Функция шифрования/расшифровывания сообщения
void Server::slotCrypt()
{
    QByteArray ba;
    char *temp;
    uint8_t *buf, *out, k[32];
    uint32_t buflen;
    int keylen;

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
    case 0 : if(salsa(k, keylen, buf, buflen, out))
                QMessageBox::warning(this, "Error!", "Salsa algorithm error!");
             break;
    case 1 : if(rabbit(k, keylen, buf, buflen, out))
                QMessageBox::warning(this, "Error!", "Rabbit algorithm error!");
             break;
    case 2 : if(hc128(k, keylen, buf, buflen, out))
                QMessageBox::warning(this, "Error!", "HC128 algorithm error!");
             break;
    case 3 : if(sosemanuk(k, keylen, buf, buflen, out))
                QMessageBox::warning(this, "Error!", "Sosemanuk algorithm error!");
             break;
    case 4 : if(grain(k, keylen, buf, buflen, out))
                QMessageBox::warning(this, "Error!", "Grain algorithm error!");
             break;
    case 5 : if(mickey(k, keylen, buf, buflen, out))
                QMessageBox::warning(this, "Error!", "Mickey algorithm error!");
             break;
    case 6 : if(trivium(k, keylen, buf, buflen, out))
                QMessageBox::warning(this, "Error!", "Trivium algorithm error!");
             break;
    }

    memcpy(temp, out, buflen);

    message.clear();
    message = QString::fromLocal8Bit(temp, buflen);

    delete[] buf;
    delete[] out;
}
