/*
 *  Copyright (C) 2010 Felix Geyer <debfx@fobos.de>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "TestCryptoHash.h"

#include <QTest>

#include "crypto/Crypto.h"
#include "crypto/CryptoHash.h"

#include <string>

QTEST_GUILESS_MAIN(TestCryptoHash)

namespace
{
const auto emptyDataHash(QByteArray::fromHex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
const auto keePassXHash(QByteArray::fromHex("0b56e5f65263e747af4a833bd7dd7ad26a64d7a4de7c68e52364893dca0766b4"));
}

void TestCryptoHash::testEmptyDataHash()
{
    CryptoHash hash(CryptoHash::Algorithm::Sha256);
    QCOMPARE(hash.result(), emptyDataHash);
}

void TestCryptoHash::testDefaultAlgorithm()
{
    CryptoHash hash;
    QCOMPARE(hash.result(), emptyDataHash);
}

void TestCryptoHash::testExampleString()
{
    QByteArray source = QString("KeePassX").toLatin1();
    QByteArray result = CryptoHash::hash(source, CryptoHash::Algorithm::Sha256);
    QCOMPARE(result, keePassXHash);
}

void TestCryptoHash::testTwoDataParts()
{
    CryptoHash hash(CryptoHash::Algorithm::Sha256);
    hash.addData(QString("KeePa").toLatin1());
    hash.addData(QString("ssX").toLatin1());
    QCOMPARE(hash.result(), keePassXHash);
}
