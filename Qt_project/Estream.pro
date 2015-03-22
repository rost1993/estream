#-------------------------------------------------
#
# Project created by QtCreator 2015-03-22T13:40:33
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = Estream
TEMPLATE = app


SOURCES += main.cpp\
        ecrypt.cpp \
    grain.cpp \
    hc128.cpp \
    mickey.cpp \
    rabbit.cpp \
    salsa.cpp \
    sosemanuk.cpp \
    trivium.cpp

HEADERS  += ecrypt.h \
    estream.h \
    grain.h \
    hc128.h \
    macro.h \
    mickey.h \
    rabbit.h \
    salsa.h \
    sosemanuk.h \
    trivium.h

FORMS    += ecrypt.ui
