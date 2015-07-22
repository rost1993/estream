/*
 * Copyright (C) 2015, Rostislav Gashin
 * <rostislav-gashin@yandex.ru>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the program. If not, see <http://www.gnu.org/licenses/lgpl-3.0.html>
 * ------------------------------------
 * POP3 mail protocol handler.
 * ------------------------------------
 * Developed: Rostislav Gashin (rost1993). The State University of Syktyvkar (Amplab).
 * Russia, Komi Republic, Syktyvkar - 21.07.2015.
*/

#include "pop3.h"

POP3::POP3()
{
}

POP3::~POP3()
{
    if(Socket)
        delete Socket;
}

// Настройка к подключению
void POP3::setInfoPOP3Server(const QString &host, int port, ConnectionType ct)
{
    this->connectionType = ct;

    switch(connectionType) {
    case TcpConnection: Socket = new QTcpSocket(this);
                        break;
    case SslConnection: Socket = new QSslSocket(this);
                        break;
    case TlsConnection: Socket = new QSslSocket(this);
                        break;
    }

    this->POP3Host = host;
    this->TcpPort = port;
}

// Настройка Email пользователя
void POP3::setEmailAddres(const QString &user, const QString &password)
{
    this->EmailUser = user;
    this->EmailPassword = password;
}

// Подключение к серверу POP3
bool POP3::ConnectToHost(void)
{
    switch(connectionType) {
    case TlsConnection:
    case TcpConnection: Socket->connectToHost(POP3Host, TcpPort);
                        break;
    case SslConnection: ((QSslSocket *)Socket)->connectToHostEncrypted(POP3Host, TcpPort);
                        break;
    }

    if(!Socket->waitForConnected(1000)) {
        return false;
    }

    // Используется медленный режим для принятия большого числа данных от сервера.
    waitForResponse();

    if(StatusConnect == -1)
        return false;

    return true;
}

// Авторизация на сервере POP3. Опции USER и PASS протокола POP3
bool POP3::AutorizationToHost(void)
{
    if(!SendMessage("user " + EmailUser))
        return false;

    waitForResponseSpeed();
    if(StatusConnect == -1)
        return false;

    if(!SendMessage("pass " + EmailPassword))
        return false;

    waitForResponseSpeed();
    if(StatusConnect == -1)
        return false;

    if(!STAT())
        return false;

    return true;
}

// Отключение от сервера. Опция QUIT протокола POP3
bool POP3::QUIT(void)
{
    SendMessage("quit");

    waitForResponseSpeed();
    if(StatusConnect == -1)
        return false;

    delete Socket;

    return true;
}

// Получаем от сервера информацию. Медленный режим работы.
// Ждем когда сервер пришлет всю информацию.
void POP3::waitForResponse(void)
{
    StatusConnect = -1;
    ResponseText.clear();
    ResponseCode.clear();
    QString Temp;

    while(Socket->waitForReadyRead(3000)) {
        if(Socket->bytesAvailable() <= 0)
            break;

        Temp = Socket->readAll();

        ResponseText += Temp;
    }

    ResponseCode = ResponseText.left(3);

    if(ResponseCode == "+OK")
        StatusConnect = 0;
}

// Получаем информацию от сервера. Быстрый режим. Не гарантирует получение всех пакетов на большом объеме.
// Используется только при авторизации.
void POP3::waitForResponseSpeed(void)
{
    StatusConnect = -1;
    ResponseText.clear();
    ResponseCode.clear();
    QString Temp;

    Socket->waitForReadyRead(3000);

    while(Socket->canReadLine()) {
        Temp = Socket->readAll();
        ResponseText += Temp;
    }

    ResponseCode = ResponseText.left(3);

    if(ResponseCode == "+OK")
        StatusConnect = 0;
}

// Отправляем сообщение POP3 серверу
bool POP3::SendMessage(const QString &message)
{
    Socket->write(message.toUtf8() + "\r\n");

    if(!Socket->waitForBytesWritten(1000))
        return false;

    return true;
}

// Выгружаем список сообщений. Опция LIST протокола POP3
bool POP3::LIST(void)
{
    MessageList.clear();

    SendMessage("list");
    waitForResponse();

    if(StatusConnect == -1)
        return false;

    MessageList = ResponseText.split("\r\n");

    MessageList.removeAt(0);
    MessageList.removeAt(MessageList.size() - 1);
    MessageList.removeAt(MessageList.size() - 1);

    MaximumMessage = MessageList.size();

    return true;
}

// Опция STAT протокола POP3
bool POP3::STAT(void)
{
    QRegExp rx("(\\d+)");
    QStringList temp;

    SendMessage("stat");

    waitForResponseSpeed();

    if(StatusConnect == -1)
        return false;

    rx.indexIn(ResponseText, 0);
    temp << rx.cap(1);
    MaximumMessage = temp[0].toInt(0, 10);

    return true;
}

// Удаление сообщения. Опция DELE протокола POP3.
// Сообщение реально удаляется после закрытия транзакции (после команды QUIT).
bool POP3::DELE(const int NumMessage)
{
    if((NumMessage == 0) || (NumMessage > MaximumMessage))
        return false;

    SendMessage("dele " + QString::number(NumMessage));

    waitForResponseSpeed();

    if(StatusConnect == -1)
        return false;

    return true;
}

// Опция протокола NOOP (POP3 сервер всегда отвечает положительно).
bool POP3::NOOP(void)
{
    SendMessage("noop");

    waitForResponseSpeed();

    if(StatusConnect == -1)
        return false;

    return true;
}

// Отмена транзакций. Опция RSET протокола POP3
bool POP3::RSET(void)
{
    SendMessage("rset");

    waitForResponseSpeed();

    if(StatusConnect == -1)
        return false;

    return true;
}

// Выгружаем заголовок письма. Опция TOP протокола POP3
bool POP3::TOP(const int NumMessage, const int Code, QStringList *HeaderMessage)
{
    if((NumMessage == 0) || (NumMessage > MaximumMessage))
        return false;

    SendMessage("top " + QString::number(NumMessage) + " " + QString::number(Code));

    waitForResponse();

    *HeaderMessage = ResponseText.split("\r\n");
    HeaderMessage->removeAt(HeaderMessage->size() - 1);
    HeaderMessage->removeAt(HeaderMessage->size() - 1);

    return true;
}

// Выгрузка письма. Опция RETR протокола POP3
bool POP3::RETR(const int NumMessage, ClientMessage *CM)
{
    QStringList List;
    int i, pos;

    if((NumMessage == 0) || (NumMessage > MaximumMessage))
        return false;

    if(!TOP(NumMessage, 0, &List))
        return false;

    // По заголовку письма выдергиваем необходимые поля.
    // ---------------------

    for(i = 0; i < List.size() - 1; i++) {

        if(List[i].indexOf(QRegExp("From:")) > -1)
            CM->Sender = List[i].mid(6, List[i].size() - 6);

        if(List[i].indexOf(QRegExp("To:")) > -1)
            CM->Recepient = List[i].mid(4, List[i].size() - 4);

        if(List[i].indexOf(QRegExp("Date:")) > -1)
            CM->Date = List[i].mid(6, List[i].size() - 6);

        if(List[i].indexOf(QRegExp("Subject:")) > -1)
            CM->Subject = List[i].mid(9, List[i].size() - 9);

        if(List[i].indexOf(QRegExp("Content-Transfer-Encoding:")) > -1)
            CM->Coding = List[i].mid(27, List[i].size() - 27);
    }

    // ---------------------

    // Выгружаем сообщение. Пытаемся найти текст письма.
    // ---------------------
    SendMessage("retr " + QString::number(NumMessage));
    waitForResponse();

    if(ResponseText.size() == 0)
        return false;

    CM->AllMessage = ResponseText;

    List.clear();
    CM->Message.clear();
    List = ResponseText.split("\r\n");

    for(i = 0; i < List.size() - 1; i++) {
        if(List[i].indexOf(QRegExp("Content-")) > -1)
            continue;

        if(List[i].size() == 0) {
            i++;

            if(List[i].indexOf(QRegExp("Content-")) > -1)
                continue;

            if(List[i+1].indexOf(QRegExp("Content-")) > -1)
                continue;

            for(; i < List.size() - 2; i++) {
                CM->Message += List[i];
            }
            break;
        }
    }
    // ---------------------

    // Отрезаем хэш-сообщения
    if((pos = CM->Message.indexOf(QRegExp("--(\\d+)"))) > -1) {
        CM->Message.remove(pos, CM->Message.size() - pos);
    }

    return true;
}
