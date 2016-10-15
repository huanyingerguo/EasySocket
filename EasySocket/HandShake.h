//
// Created by baidu on 16/2/1.
// Copyright (c) 2016 isee15. All rights reserved.
//

#ifndef DEMONET_HANDSHAKE_H
#define DEMONET_HANDSHAKE_H

#include <string>
#include <iostream>

#import "CT.h"
#include "IMRSA.h"

const std::string dataForS1();

const std::string dataForS3(const unsigned char *data, IMRSA *m_MyRSA);

#endif //DEMONET_HANDSHAKE_H
