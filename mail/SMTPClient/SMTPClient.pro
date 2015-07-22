#-------------------------------------------------
#
# Project created by QtCreator 2015-06-11T22:39:04
#
#-------------------------------------------------

QT       += core gui network serialport

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

LIBS += -L"../src/" -lsmtpemail

TARGET = SMTPClient
TEMPLATE = app


SOURCES += main.cpp\
        clientsmtp.cpp \
    settings.cpp \
    ../lib/gost89.cpp \
    ../lib/grain.cpp \
    ../lib/hc128.cpp \
    ../lib/mickey.cpp \
    ../lib/rabbit.cpp \
    ../lib/salsa.cpp \
    ../lib/sosemanuk.cpp \
    ../lib/trivium.cpp

HEADERS  += clientsmtp.h \
    settings.h \
    ../src/SmtpMime \
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

FORMS    += clientsmtp.ui \
    settings.ui
