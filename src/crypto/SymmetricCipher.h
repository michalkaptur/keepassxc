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

#ifndef KEEPASSX_SYMMETRICCIPHER_H
#define KEEPASSX_SYMMETRICCIPHER_H

#include <QByteArray>
#include <QScopedPointer>
#include <QString>

#include "crypto/SymmetricCipherBackend.h"
#include "format/KeePass2.h"

class SymmetricCipher
{
public:
    enum class Algorithm
    {
        Aes256,
        Twofish,
        Salsa20
    };

    enum class Mode
    {
        Cbc,
        Ecb,
        Stream
    };

    enum class Direction
    {
        Decrypt,
        Encrypt
    };

    SymmetricCipher(Algorithm algo, Mode mode, Direction direction);
    ~SymmetricCipher() = default;

    bool init(const QByteArray& key, const QByteArray& iv);
    bool isInitalized() const;

    inline QByteArray process(const QByteArray& data, bool* ok) {
        return m_backend->process(data, ok);
    }

    Q_REQUIRED_RESULT inline bool processInPlace(QByteArray& data) {
        return m_backend->processInPlace(data);
    }

    Q_REQUIRED_RESULT inline bool processInPlace(QByteArray& data, quint64 rounds) {
        Q_ASSERT(rounds > 0);
        return m_backend->processInPlace(data, rounds);
    }

    bool reset();
    int blockSize() const;
    QString errorString() const;

    static Algorithm cipherToAlgorithm(Uuid cipher);
    static Uuid algorithmToCipher(Algorithm algo);

private:
    static SymmetricCipherBackend* createBackend(Algorithm algo, Mode mode,
                                                 Direction direction);

    const QScopedPointer<SymmetricCipherBackend> m_backend;
    bool m_initialized;

    Q_DISABLE_COPY(SymmetricCipher)
};

#endif // KEEPASSX_SYMMETRICCIPHER_H
