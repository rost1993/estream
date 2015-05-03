#-------------------------------------------------
#
# Project created by QtCreator 2015-04-28T20:36:28
#
#-------------------------------------------------

QT       += core gui network

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = server
TEMPLATE = app


SOURCES += main.cpp\
        server.cpp \
    ../lib/grain.cpp \
    ../lib/hc128.cpp \
    ../lib/mickey.cpp \
    ../lib/rabbit.cpp \
    ../lib/salsa.cpp \
    ../lib/sosemanuk.cpp \
    ../lib/trivium.cpp

HEADERS  += server.h \
    ../lib/estream.h \
    ../lib/grain.h \
    ../lib/hc128.h \
    ../lib/macro.h \
    ../lib/mickey.h \
    ../lib/rabbit.h \
    ../lib/salsa.h \
    ../lib/sosemanuk.h \
    ../lib/trivium.h

FORMS    += server.ui
