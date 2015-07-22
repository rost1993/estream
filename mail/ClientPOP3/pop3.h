/*
 * Первая собственная попытка реализации обработчика почтового протокола POP3.
 * ------------------------------------
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

#include <QRegExp>
#include <QObject>
#include <QTcpSocket>
#include <QSslSocket>
#include <QStringList>
#include <QtNetwork/QSslSocket>

#ifndef POP3_H
#define POP3_H


class POP3: public QObject
{
    Q_OBJECT
public:
    POP3();
    ~POP3();

    enum ConnectionType {
        TcpConnection,
        SslConnection,
        TlsConnection
    };

    QStringList MessageList;
    int MaximumMessage;

    bool ConnectToHost(void);
    bool AutorizationToHost(void);
    bool SendMessage(const QString &message);
    bool QUIT(void);
    bool LIST(void);
    bool STAT(void);
    bool DELE(const int NumMessage);
    bool NOOP(void);
    bool RSET(void);
    bool RETR(const int NumMessage, struct ClientMessage *CM);
    bool TOP(const int NumMessage, const int Code, QStringList *HeaderMessage);

    void setInfoPOP3Server(const QString &host, int port, ConnectionType ct);
    void setEmailAddres(const QString &user, const QString &password);


protected:
    QTcpSocket *Socket;
    ConnectionType connectionType;
    QString POP3Host;
    QString EmailUser;
    QString EmailPassword;
    int TcpPort;

    QString ResponseText;
    QString ResponseCode;
    int StatusConnect;

    void waitForResponse(void);
    void waitForResponseSpeed(void);
};

struct ClientMessage {
    QString AllMessage;
    QString Subject;
    QString Date;
    QString Sender;
    QString Recepient;
    QString Message;
    QString Coding;
};

#endif // POP3_H
