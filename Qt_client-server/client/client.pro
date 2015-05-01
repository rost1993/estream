#-------------------------------------------------
#
# Project created by QtCreator 2015-04-28T22:34:03
#
#-------------------------------------------------

QT       += core gui network

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = client
TEMPLATE = app


SOURCES += main.cpp\
        client.cpp \
    ../lib/grain.cpp \
    ../lib/hc128.cpp \
    ../lib/mickey.cpp \
    ../lib/rabbit.cpp \
    ../lib/salsa.cpp \
    ../lib/sosemanuk.cpp \
    ../lib/trivium.cpp \
    settings.cpp

HEADERS  += client.h \
    ../lib/estream.h \
    ../lib/grain.h \
    ../lib/hc128.h \
    ../lib/macro.h \
    ../lib/mickey.h \
    ../lib/rabbit.h \
    ../lib/salsa.h \
    ../lib/sosemanuk.h \
    ../lib/trivium.h \
    settings.h

FORMS    += client.ui \
    settings.ui
