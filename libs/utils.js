/**
 * [formatDate use time or not]
 *  example default result
 * if TRUE {[2020-04-15]} else {[2020-04-15 22:27:33]}
 *
 * @param  {[type]}  date        [description]
 * @param  {Boolean} [opt=false] [default]
 * @return {[type]}              [description]
 */
function formatDateStandard(date, opt = false){
    let a = new Date(date);

    let year = a.getFullYear()
    let month = ("0" + (a.getMonth() + 1)).slice(-2)
    let day = ("0" + a.getDate()).slice(-2)
    let hour = ("0" + a.getHours()).slice(-2)
    let min = ("0" + a.getMinutes()).slice(-2)
    let sec = ("0" + a.getSeconds()).slice(-2)
    let result = ''
    if (opt) result = year + '-' + month + '-' + day+ ' '+hour+':'+min+':'+ sec
    else result = year + '-' + month + '-' + day
    return result
}

/**
 * [formatRupiah using ext 00 or not]
 *
 * if TRUE [RP 100.000.00] else [RP 100.000]
 *
 * @param  {[type]}  number        [description]
 * @param  {Boolean} [type=false] [default]
 * @return {[type]}               [description]
 */
function formatRupiah(angka, type= false){
    let ext = ''
    if (type) ext = '.00'
    let reverse = angka.toString().split('').reverse().join(''),
    ribuan = reverse.match(/\d{1,3}/g)
    ribuan = ribuan.join('.').split('').reverse().join('')
    return `RP ${ribuan}`+ext
}

function formatMontYear(date) {
    const monthNames = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Okt", "Nov", "Des"]

    let dy = new Date(date)

    return monthNames[dy.getMonth()] + '-' + dy.getFullYear()
}

function handleErrorValidation(array) {
    return array.reduce(
        (obj, item) => (obj['message'] = {field: item.dataPath, message: item.dataPath+' '+item.message}, obj) ,{}
    );
}

//using internatiopnal standard phone number
function reformatPhoneNumber(phone) {
    let valid_phone = ''

    if (phone[0] === '0') {
        valid_phone = '62'+phone.substr(1, phone.length)
    }else{
        valid_phone = phone
    }
    return valid_phone
}

module.exports = {
    formatDateStandard,
    formatRupiah,
    formatMontYear,
    handleErrorValidation,
    reformatPhoneNumber
}
