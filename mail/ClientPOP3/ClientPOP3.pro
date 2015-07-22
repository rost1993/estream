#-------------------------------------------------
#
# Project created by QtCreator 2015-06-12T08:14:28
#
#-------------------------------------------------

QT       += core gui network serialport

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = ClientPOP3
TEMPLATE = app


SOURCES += main.cpp\
        clientpop3.cpp \
    pop3.cpp \
    settings.cpp \
    ../lib/gost89.cpp \
    ../lib/grain.cpp \
    ../lib/hc128.cpp \
    ../lib/mickey.cpp \
    ../lib/rabbit.cpp \
    ../lib/salsa.cpp \
    ../lib/sosemanuk.cpp \
    ../lib/trivium.cpp

HEADERS  += clientpop3.h \
    pop3.h \
    settings.h \
    ../lib/estream.h \
    ../lib/gost89.h \
    ../lib/grain.h \
    ../lib/hc128.h \
    ../lib/macro.h \
    ../lib/mickey.h \
    ../lib/rabbit.h \
    ../lib/salsa.h \
    ../lib/sosemanuk.h \
    ../lib/trivium.h

FORMS    += clientpop3.ui \
    settings.ui
