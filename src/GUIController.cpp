#include "datastego/GUIController.hpp"
#include "datastego/ContainerFormat.hpp"
#include "datastego/FileIO.hpp"
#include "datastego/ImageHandler.hpp"
#include "datastego/StegoEngine.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <algorithm>
#include <array>
#include <cmath>
#include <cwctype>
#include <filesystem>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#ifndef WC_ERR_INVALID_CHARS
#define WC_ERR_INVALID_CHARS 0x00000080
#endif
#ifndef PBS_MARQUEE
#define PBS_MARQUEE 0x08
#endif
#ifndef PBM_SETMARQUEE
#define PBM_SETMARQUEE (WM_USER + 10)
#endif

namespace datastego {
namespace {
constexpr wchar_t WindowClass[] = L"DataStego.MainWindow.v1";
constexpr UINT WorkDone = WM_APP + 1;
constexpr COLORREF Background = RGB(245,248,246), Panel = RGB(255,255,255);
constexpr COLORREF Ink = RGB(25,46,39), Muted = RGB(100,117,109);
constexpr COLORREF Accent = RGB(19,135,96), AccentPressed = RGB(13,108,77);
constexpr COLORREF Border = RGB(218,229,222), SoftGreen = RGB(232,246,237);
constexpr COLORREF ErrorRed = RGB(184,53,53);

enum Id : int {
    HomeHide=1001, HomeExtract=1002, Back=1003,
    BrowseImage=1101, BrowseSecret=1102, BrowseOutput=1103,
    ImagePath=1201, SecretPath=1202, OutputPath=1203, Password=1204,
    ShowPassword=1205, Capacity=1206, Action=1301, Progress=1302, Status=1303,
    ResultTitle=1401, ResultBody=1402, ResultPath=1403, ResultHome=1404, Exit=1405
};
enum class Page { Home, Hide, Extract, Success, Failure };
enum class WorkKind { Inspect, Hide, Extract, SaveExtract };

std::wstring fromUtf8(const std::string& text) {
    if (text.empty()) return {};
    const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (size <= 0) return L"Не удалось прочитать текст сообщения.";
    std::wstring out(static_cast<std::size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), &out[0], size);
    return out;
}
Bytes passwordBytes(const std::wstring& text) {
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0 || size > 4096) throw Error("Invalid password text");
    Bytes bytes(static_cast<std::size_t>(size));
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()),
                        reinterpret_cast<char*>(bytes.data()), size, nullptr, nullptr);
    return bytes;
}
std::size_t characterCount(const std::wstring& text) {
    std::size_t count = 0;
    for (std::size_t i = 0; i < text.size(); ++i, ++count)
        if (text[i] >= 0xd800 && text[i] <= 0xdbff && i + 1 < text.size() && text[i+1] >= 0xdc00 && text[i+1] <= 0xdfff) ++i;
    return count;
}
std::wstring formatBytes(std::uint64_t count) {
    std::wostringstream out;
    if (count >= 1024 * 1024) out << std::fixed << std::setprecision(2) << (double(count) / (1024*1024)) << L" МиБ";
    else if (count >= 1024) out << std::fixed << std::setprecision(1) << (double(count) / 1024) << L" КиБ";
    else out << count << L" байт";
    return out.str();
}
std::wstring explainError(const std::exception& error) {
    const std::string text = error.what();
    const std::vector<std::pair<std::string, std::wstring>> messages = {
        {"Authentication failed", L"Пароль неверный или скрытые данные повреждены. Проверьте пароль и убедитесь, что изображение не изменяли после создания контейнера."},
        {"No DataStego container", L"В выбранном изображении не найден контейнер DataStego. Выберите PNG, созданный этой программой."},
        {"Payload length exceeds", L"В изображении недостаточно места для заголовка или данные повреждены."},
        {"Cannot open input", L"Не удалось открыть файл. Проверьте, существует ли он, и есть ли разрешение на чтение."},
        {"Cannot create output", L"Не удалось сохранить результат. Проверьте папку, права доступа и не открыт ли файл в другой программе."},
        {"Cannot write output", L"Не удалось записать файл целиком. Проверьте свободное место и доступ к выбранной папке."},
        {"Input exceeds", L"Файл слишком большой для обработки. Выберите файл меньшего размера."},
        {"Expected a PNG or BMP", L"Нужен файл PNG или несжатый BMP. JPEG не поддерживается: он меняет младшие биты цветов."},
        {"Image is too small", L"Изображение слишком маленькое для выбранного файла. Выберите изображение с большей вместимостью."},
        {"PNG chunk CRC32", L"PNG повреждён: контрольная сумма одного из его блоков не совпадает."},
        {"Unsupported BMP", L"Этот вариант BMP не поддерживается. Используйте PNG или несжатый BMP 24/32 бита."},
        {"BMP must be", L"Используйте несжатый BMP с глубиной 24/32 бита или изображение PNG."},
        {"Invalid password text", L"Не удалось прочитать пароль. Используйте корректный текст длиной до 1024 символов."},
        {"Invalid filename", L"Недопустимое имя исходного файла. Используйте имя длиной до 255 байтов без управляющих символов."},
        {"Invalid payload length", L"Заголовок скрытых данных повреждён или не соответствует размеру изображения."},
        {"Invalid PBKDF2", L"Параметры скрытого контейнера повреждены или не поддерживаются."},
        {"Unsupported container", L"Этот контейнер создан неподдерживаемой версией программы."},
        {"memory limit", L"Изображение слишком большое для обработки. Выберите изображение меньшего размера."},
        {"256 MiB", L"Изображение превышает допустимый размер. Выберите изображение меньшего размера."}
    };
    for (const auto& message : messages) if (text.find(message.first) != std::string::npos) return message.second;
    if (dynamic_cast<const std::bad_alloc*>(&error)) return L"Недостаточно оперативной памяти. Выберите изображение меньшего размера.";
    if (text.find("PNG") != std::string::npos || text.find("DEFLATE") != std::string::npos || text.find("BMP") != std::string::npos)
        return L"Не удалось прочитать изображение: файл повреждён или его формат не поддерживается.";
    if (std::any_of(text.begin(), text.end(), [](unsigned char c) { return c >= 128; })) return fromUtf8(text);
    return L"Не удалось обработать файл. Проверьте выбранные файлы и доступ к папке сохранения.\n" + fromUtf8(text);
}

struct WorkItem {
    HWND owner = nullptr;
    WorkKind kind = WorkKind::Inspect;
    bool extractInspection = false, overwrite = false;
    std::filesystem::path imagePath, filePath, outputPath;
    std::shared_ptr<const Image> image;
    SecretBytes password;
    std::unique_ptr<RecoveredFile> recovered;
};
struct WorkResult {
    WorkKind kind = WorkKind::Inspect;
    bool success = false;
    std::wstring message;
    std::filesystem::path imagePath, outputPath;
    std::shared_ptr<const Image> image;
    std::uint64_t fileSize = 0;
    double psnr = 0;
    std::unique_ptr<RecoveredFile> recovered;
};

DWORD WINAPI workerEntry(void* argument) {
    std::unique_ptr<WorkItem> work(static_cast<WorkItem*>(argument));
    std::unique_ptr<WorkResult> result;
    try {
        result = std::make_unique<WorkResult>();
        result->kind = work->kind;
        result->imagePath = work->imagePath;
        result->outputPath = work->outputPath;
        if (work->kind == WorkKind::SaveExtract) {
            if (!work->recovered) throw Error("Missing recovered file");
            if (sameFile(work->imagePath, work->outputPath))
                throw Error("Выходной файл должен отличаться от изображения-контейнера. Выберите другое имя.");
            writeFile(work->outputPath, work->recovered->data, work->overwrite);
            result->fileSize = work->recovered->data.size();
            result->success = true;
            if (PostMessageW(work->owner, WorkDone, 0, reinterpret_cast<LPARAM>(result.get()))) result.release();
            return 0;
        }
        const auto source = work->image ? work->image : std::make_shared<const Image>(ImageHandler::load(work->imagePath));
        if (work->kind == WorkKind::Inspect) {
            if (work->extractInspection) {
                const auto header = StegoEngine::extract(*source, ContainerFormat::HeaderSize);
                ContainerFormat::inspect(header, source->capacityBytes());
            }
            result->image = source;
        } else {
            if (work->kind == WorkKind::Hide && (sameFile(work->imagePath, work->outputPath) ||
                sameFile(work->filePath, work->outputPath)))
                throw Error("Выходной файл должен отличаться от исходных файлов. Выберите другое имя.");
            const std::string_view password(reinterpret_cast<const char*>(work->password.bytes.data()), work->password.bytes.size());
            if (work->kind == WorkKind::Hide) {
                SecretBytes file(readFile(work->filePath));
                const auto filename = work->filePath.filename().u8string();
                const auto size = ContainerFormat::packedSize(file.bytes.size(), filename.size());
                if (size > source->capacityBytes())
                    throw Error("Изображение не вмещает этот файл. Выберите более крупное изображение или файл меньшего размера.");
                const auto container = ContainerFormat::pack(file.bytes, filename, password);
                Image stego = *source;
                StegoEngine::embed(stego, container);
                result->psnr = ImageHandler::psnr(*source, stego);
                ImageHandler::savePng(stego, work->outputPath, work->overwrite);
                result->fileSize = file.bytes.size();
            } else {
                const auto header = StegoEngine::extract(*source, ContainerFormat::HeaderSize);
                const auto info = ContainerFormat::inspect(header, source->capacityBytes());
                const auto container = StegoEngine::extract(*source, ContainerFormat::HeaderSize + static_cast<std::size_t>(info.ciphertextSize));
                result->recovered = std::make_unique<RecoveredFile>(ContainerFormat::unpack(container, password));
                result->fileSize = result->recovered->data.size();
            }
        }
        result->success = true;
    } catch (const std::exception& error) {
        if (result) {
            try { result->message = explainError(error); }
            catch (...) { result->message.clear(); }
        }
    } catch (...) { if (result) result->message.clear(); }


    if (PostMessageW(work->owner, WorkDone, 0, reinterpret_cast<LPARAM>(result.get()))) result.release();
    return 0;
}

class Application {
public:
    Application() : instance_(GetModuleHandleW(nullptr)) {
        const auto dc = GetDC(nullptr);
        dpi_ = dc ? GetDeviceCaps(dc, LOGPIXELSX) : 96;
        if (dc) ReleaseDC(nullptr, dc);
        if (dpi_ <= 0) dpi_ = 96;
        normal_ = font(10, FW_NORMAL); bold_ = font(10, FW_SEMIBOLD);
        heading_ = font(22, FW_SEMIBOLD); brand_ = font(17, FW_SEMIBOLD);
        resultFont_ = font(25, FW_SEMIBOLD);
        backgroundBrush_ = CreateSolidBrush(Background); panelBrush_ = CreateSolidBrush(Panel);
        icon_ = LoadIconW(instance_, MAKEINTRESOURCEW(101));
    }
    ~Application() {
        if (worker_) { WaitForSingleObject(worker_, INFINITE); CloseHandle(worker_); }
        for (auto f : {normal_,bold_,heading_,brand_,resultFont_}) if (f) DeleteObject(f);
        if (backgroundBrush_) DeleteObject(backgroundBrush_);
        if (panelBrush_) DeleteObject(panelBrush_);
    }
    int run(int showCommand) {
        INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES};
        InitCommonControlsEx(&controls);
        WNDCLASSEXW windowClass{};
        windowClass.cbSize = sizeof(windowClass);
        windowClass.style = CS_HREDRAW | CS_VREDRAW;
        windowClass.lpfnWndProc = windowProcedure;
        windowClass.hInstance = instance_;
        windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        windowClass.hIcon = icon_; windowClass.hIconSm = icon_;
        windowClass.lpszClassName = WindowClass;
        if (!RegisterClassExW(&windowClass) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
            throw Error("Cannot register application window");
        RECT work{}; SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
        const int width = std::min(s(960), int(work.right - work.left - 24));
        const int height = std::min(s(760), int(work.bottom - work.top - 24));
        hwnd_ = CreateWindowExW(WS_EX_CONTROLPARENT, WindowClass, L"DataStego: защита файлов",
            WS_OVERLAPPEDWINDOW, work.left + (work.right-work.left-width)/2,
            work.top + (work.bottom-work.top-height)/2, width, height,
            nullptr, nullptr, instance_, this);
        if (!hwnd_) throw Error("Cannot create application window");
        ShowWindow(hwnd_, showCommand);
        UpdateWindow(hwnd_);
        MSG message{};
        int status = 0;
        while ((status = GetMessageW(&message, nullptr, 0, 0)) > 0) {
            if (!IsDialogMessageW(hwnd_, &message)) { TranslateMessage(&message); DispatchMessageW(&message); }
        }
        return status < 0 ? 1 : static_cast<int>(message.wParam);
    }
private:
    HINSTANCE instance_ = nullptr;
    HWND hwnd_ = nullptr;
    HANDLE worker_ = nullptr;
    int dpi_ = 96;
    HFONT normal_=nullptr, bold_=nullptr, heading_=nullptr, brand_=nullptr, resultFont_=nullptr;
    HBRUSH backgroundBrush_=nullptr, panelBrush_=nullptr;
    HICON icon_ = nullptr;
    Page page_ = Page::Home;
    bool busy_ = false, building_ = false;
    std::vector<HWND> children_;
    std::shared_ptr<const Image> image_;
    std::filesystem::path cachedPath_, approvedOverwrite_;
    std::wstring resultBody_, resultPath_;

    int s(int value) const { return MulDiv(value, dpi_, 96); }
    HFONT font(int points, int weight) const {
        return CreateFontW(-MulDiv(points,dpi_,72),0,0,0,weight,FALSE,FALSE,FALSE,DEFAULT_CHARSET,
                          OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");
    }
    HWND child(int id) const { return GetDlgItem(hwnd_, id); }
    std::wstring text(int id) const {
        const auto window = child(id);
        if (!window) return {};
        const auto length = GetWindowTextLengthW(window);
        std::wstring result(static_cast<std::size_t>(length) + 1, L'\0');
        const auto read = GetWindowTextW(window, &result[0], length + 1);
        result.resize(static_cast<std::size_t>(read));
        return result;
    }
    void setText(int id, const std::wstring& value) { if (child(id)) SetWindowTextW(child(id), value.c_str()); }
    HWND control(const wchar_t* type, const std::wstring& title, int id, DWORD style=0, DWORD extended=0, HFONT selected=nullptr) {
        auto window = CreateWindowExW(extended,type,title.c_str(),WS_CHILD | WS_VISIBLE | style,
            0,0,1,1,hwnd_,reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),instance_,nullptr);
        if (!window) throw Error("Cannot create window control");
        SendMessageW(window,WM_SETFONT,reinterpret_cast<WPARAM>(selected ? selected : normal_),FALSE);
        children_.push_back(window);
        return window;
    }
    void button(int id, const std::wstring& title) {
        control(L"BUTTON",title,id,BS_OWNERDRAW | WS_TABSTOP,0,bold_);
    }
    void label(int id, const std::wstring& title, HFONT selected=nullptr) {
        control(L"STATIC",title,id,SS_LEFT | SS_NOPREFIX,0,selected);
    }
    void edit(int id, bool readonly=false, bool password=false, bool multiline=false) {
        DWORD style = WS_TABSTOP | ES_LEFT | (multiline ? ES_MULTILINE | ES_AUTOVSCROLL : ES_AUTOHSCROLL);
        if (readonly) style |= ES_READONLY;
        if (password) style |= ES_PASSWORD;
        const auto field = control(L"EDIT",L"",id,style,WS_EX_CLIENTEDGE);
        SendMessageW(field,EM_SETLIMITTEXT,password ? 1024 : 32767,0);
        if (password) SendMessageW(field,EM_SETPASSWORDCHAR,0x25cf,0);
    }
    void move(int id,int x,int y,int width,int height) {
        if (const auto window = child(id)) MoveWindow(window,s(x),s(y),s(width),s(height),TRUE);
    }
    void clearControls() {
        setText(Password,L"");
        for (auto window : children_) DestroyWindow(window);
        children_.clear();
    }
    void page(Page next) {
        building_ = true;
        clearControls(); page_ = next;
        if (next == Page::Home) {
            image_.reset(); cachedPath_.clear(); approvedOverwrite_.clear();
            button(HomeHide,L"Спрятать файл"); button(HomeExtract,L"Извлечь файл");
        } else if (next == Page::Hide || next == Page::Extract) {
            image_.reset(); cachedPath_.clear(); approvedOverwrite_.clear();
            button(Back,L"← Главное меню");
            label(2001,next == Page::Hide ? L"Изображение-контейнер" : L"Изображение со скрытым файлом",bold_);
            edit(ImagePath,true); button(BrowseImage,L"Выбрать файл…");
            label(Capacity,next == Page::Hide ? L"Выберите PNG или BMP, чтобы узнать вместимость." : L"Выберите PNG-контейнер, созданный в DataStego.");
            if (next == Page::Hide) {
                label(2002,L"Файл, который нужно спрятать",bold_);
                edit(SecretPath,true); button(BrowseSecret,L"Выбрать файл…");
            }
            if (next == Page::Hide) {
                label(2003,L"Имя и место сохранения нового PNG",bold_);
                edit(OutputPath); button(BrowseOutput,L"Сохранить как…");
            } else {
                label(2003,L"Исходное имя и расширение восстановятся автоматически.");
                label(2007,L"После проверки пароля выберите папку в окне сохранения.");
            }
            label(2004,next == Page::Hide ? L"Пароль (минимум 8 символов)" : L"Пароль от контейнера",bold_);
            edit(Password,false,true);
            control(L"BUTTON",L"Показать пароль",ShowPassword,BS_AUTOCHECKBOX | WS_TABSTOP);
            label(2005,next == Page::Hide ? L"Сохраните пароль: он понадобится для восстановления файла." : L"При неверном пароле файл не будет записан.");
            control(PROGRESS_CLASSW,L"",Progress,PBS_MARQUEE);
            ShowWindow(child(Progress),SW_HIDE);
            label(Status,L"");
            button(Action,next == Page::Hide ? L"Зашифровать и спрятать" : L"Извлечь файл");
        } else {
            const bool ok = next == Page::Success;
            label(ResultTitle,ok ? L"Успешно" : L"Не удалось выполнить операцию",resultFont_);
            SetWindowLongPtrW(child(ResultTitle),GWL_STYLE,GetWindowLongPtrW(child(ResultTitle),GWL_STYLE) | SS_CENTER);
            label(ResultBody,resultBody_);
            SetWindowLongPtrW(child(ResultBody),GWL_STYLE,GetWindowLongPtrW(child(ResultBody),GWL_STYLE) | SS_CENTER);
            if (ok && !resultPath_.empty()) { edit(ResultPath,true,false,true); setText(ResultPath,resultPath_); }
            label(2006,L"Вернуться в главное меню?");
            SetWindowLongPtrW(child(2006),GWL_STYLE,GetWindowLongPtrW(child(2006),GWL_STYLE) | SS_CENTER);
            button(ResultHome,L"Главное меню"); button(Exit,L"Выйти");
        }
        building_ = false;
        layout(); InvalidateRect(hwnd_,nullptr,FALSE);
        if (next == Page::Home) SetFocus(child(HomeHide));
        else if (next == Page::Hide || next == Page::Extract) SetFocus(child(BrowseImage));
        else SetFocus(child(ResultHome));
    }
    void layout() {
        RECT client{}; GetClientRect(hwnd_,&client);
        const int w=MulDiv(client.right,96,dpi_), h=MulDiv(client.bottom,96,dpi_);
        if (page_ == Page::Home) {
            const int card=(w-88)/2;
            move(HomeHide,56,365,card-48,46);
            move(HomeExtract,56+card+24,365,card-48,46);
        } else if (page_ == Page::Hide || page_ == Page::Extract) {
            move(Back,32,111,154,32);
            const int fieldWidth=w-252;
            move(2001,52,218,w-104,22);
            move(ImagePath,52,243,fieldWidth,34); move(BrowseImage,w-184,243,132,34);
            move(Capacity,52,282,w-104,24);
            const bool hide=page_ == Page::Hide;
            if (hide) { move(2002,52,309,w-104,22); move(SecretPath,52,334,fieldWidth,34); move(BrowseSecret,w-184,334,132,34); }
            const int outY=hide ? 378 : 309;
            move(2003,52,outY,w-104,22); move(OutputPath,52,outY+25,fieldWidth,34); move(BrowseOutput,w-184,outY+25,132,34);
            move(2007,52,outY+25,w-104,24);
            const int pwdY=hide ? 447 : 378;
            move(2004,52,pwdY,w-104,22); move(Password,52,pwdY+25,w-280,34);
            move(ShowPassword,w-208,pwdY+27,156,30); move(2005,52,pwdY+64,w-104,24);
            move(Progress,52,h-119,w-104,6); move(Status,52,h-108,w-104,22);
            move(Action,w-304,h-65,272,42);
        } else {
            move(ResultTitle,80,266,w-160,48); move(ResultBody,104,323,w-208,76);
            move(ResultPath,104,403,w-208,46);
            move(2006,104,h-173,w-208,24);
            move(ResultHome,w/2-204,h-135,196,42); move(Exit,w/2+8,h-135,196,42);
        }
    }
    void rounded(HDC dc,int x,int y,int w,int h,COLORREF fill,COLORREF line,int radius=14) const {
        const auto brush=CreateSolidBrush(fill); const auto pen=CreatePen(PS_SOLID,1,line);
        const auto oldBrush=SelectObject(dc,brush), oldPen=SelectObject(dc,pen);
        RoundRect(dc,s(x),s(y),s(x+w),s(y+h),s(radius),s(radius));
        SelectObject(dc,oldBrush); SelectObject(dc,oldPen); DeleteObject(brush); DeleteObject(pen);
    }
    void drawText(HDC dc,const std::wstring& value,int x,int y,int w,int h,HFONT selected,COLORREF color,UINT flags=DT_LEFT | DT_WORDBREAK) const {
        RECT area{s(x),s(y),s(x+w),s(y+h)};
        const auto old=SelectObject(dc,selected); SetBkMode(dc,TRANSPARENT); SetTextColor(dc,color);
        DrawTextW(dc,value.c_str(),static_cast<int>(value.size()),&area,flags | DT_NOPREFIX);
        SelectObject(dc,old);
    }
    void paint(HDC requested=nullptr) {
        PAINTSTRUCT ps{}; const auto target=requested ? requested : BeginPaint(hwnd_,&ps);
        RECT client{}; GetClientRect(hwnd_,&client);
        const auto dc=CreateCompatibleDC(target); const auto bitmap=CreateCompatibleBitmap(target,client.right,client.bottom);
        const auto oldBitmap=SelectObject(dc,bitmap);
        FillRect(dc,&client,backgroundBrush_);
        const int w=MulDiv(client.right,96,dpi_), h=MulDiv(client.bottom,96,dpi_);
        if (icon_) DrawIconEx(dc,s(32),s(25),icon_,s(36),s(36),0,nullptr,DI_NORMAL);
        drawText(dc,L"DataStego",80,23,w-112,35,brand_,Ink);
        drawText(dc,L"Защита файлов внутри изображений",32,72,w-64,24,normal_,Muted);
        const auto separator=CreatePen(PS_SOLID,1,Border);
        const auto oldPen=SelectObject(dc,separator);
        MoveToEx(dc,s(32),s(104),nullptr); LineTo(dc,s(w-32),s(104)); SelectObject(dc,oldPen); DeleteObject(separator);
        if (page_ == Page::Home) {
            drawText(dc,L"Что нужно сделать?",32,145,w-64,46,heading_,Ink);
            drawText(dc,L"Выберите действие. Программа проведёт вас по шагам.",32,192,w-64,35,normal_,Muted);
            const int card=(w-88)/2;
            rounded(dc,32,242,card,197,Panel,Border); rounded(dc,56+card,242,card,197,Panel,Border);
            drawText(dc,L"01",56,261,48,32,brand_,Accent);
            drawText(dc,L"Спрятать файл",56,303,card-48,32,brand_,Ink);
            drawText(dc,L"Зашифровать документ и сохранить его в PNG.",56,337,card-48,26,normal_,Muted);
            drawText(dc,L"02",80+card,261,48,32,brand_,Accent);
            drawText(dc,L"Извлечь файл",80+card,303,card-48,32,brand_,Ink);
            drawText(dc,L"Восстановить исходный файл по паролю.",80+card,337,card-48,26,normal_,Muted);
            rounded(dc,32,468,w-64,82,SoftGreen,SoftGreen);
            drawText(dc,L"Подготовьте изображение PNG или BMP и придумайте пароль.",52,486,w-104,25,bold_,Ink);
            drawText(dc,L"Изображение с данными сохраняется как новый PNG-файл.",52,513,w-104,24,normal_,Muted);
        } else if (page_ == Page::Hide || page_ == Page::Extract) {
            const bool hide=page_ == Page::Hide;
            drawText(dc,hide ? L"Спрятать файл" : L"Извлечь файл",32,151,w-64,40,heading_,Ink);
            drawText(dc,hide ? L"Выберите изображение, файл и место сохранения." : L"Выберите контейнер и введите пароль от скрытого файла.",32,190,w-64,24,normal_,Muted);
            rounded(dc,32,208,w-64,h-288,Panel,Border);
        } else {
            rounded(dc,64,174,w-128,h-246,Panel,Border);
            const bool success=page_ == Page::Success;
            const auto badge=CreateSolidBrush(success ? SoftGreen : RGB(253,234,234));
            const auto oldBrush=SelectObject(dc,badge); const auto nullPen=SelectObject(dc,GetStockObject(NULL_PEN));
            Ellipse(dc,s(w/2-27),s(203),s(w/2+27),s(257));
            SelectObject(dc,oldBrush); SelectObject(dc,nullPen); DeleteObject(badge);
            const auto symbol=CreatePen(PS_SOLID,s(3),success ? Accent : ErrorRed);
            const auto old=SelectObject(dc,symbol);
            if (success) { MoveToEx(dc,s(w/2-12),s(230),nullptr); LineTo(dc,s(w/2-3),s(239)); LineTo(dc,s(w/2+14),s(221)); }
            else { MoveToEx(dc,s(w/2-9),s(221),nullptr); LineTo(dc,s(w/2+9),s(239)); MoveToEx(dc,s(w/2+9),s(221),nullptr); LineTo(dc,s(w/2-9),s(239)); }
            SelectObject(dc,old); DeleteObject(symbol);
        }
        BitBlt(target,0,0,client.right,client.bottom,dc,0,0,SRCCOPY);
        SelectObject(dc,oldBitmap); DeleteObject(bitmap); DeleteDC(dc);
        if (!requested) EndPaint(hwnd_,&ps);
    }
    void drawButton(const DRAWITEMSTRUCT& item) const {
        const bool primary=item.CtlID == HomeHide || item.CtlID == Action || item.CtlID == ResultHome;
        const bool pressed=(item.itemState & ODS_SELECTED) != 0, disabled=(item.itemState & ODS_DISABLED) != 0;
        COLORREF fill=primary ? (pressed ? AccentPressed : Accent) : (pressed ? SoftGreen : Panel);
        if (disabled) fill=primary ? RGB(157,190,173) : RGB(241,244,242);
        const auto brush=CreateSolidBrush(fill);
        const auto pen=CreatePen(PS_SOLID,1,primary ? fill : Border);
        const auto oldBrush=SelectObject(item.hDC,brush), oldPen=SelectObject(item.hDC,pen);
        RoundRect(item.hDC,item.rcItem.left,item.rcItem.top,item.rcItem.right,item.rcItem.bottom,s(10),s(10));
        SelectObject(item.hDC,oldBrush); SelectObject(item.hDC,oldPen); DeleteObject(brush); DeleteObject(pen);
        const auto oldFont=SelectObject(item.hDC,bold_); SetBkMode(item.hDC,TRANSPARENT);
        SetTextColor(item.hDC,disabled ? RGB(111,132,121) : primary ? RGB(255,255,255) : Ink);
        auto area=item.rcItem; const auto caption=text(static_cast<int>(item.CtlID));
        DrawTextW(item.hDC,caption.c_str(),static_cast<int>(caption.size()),&area,DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        if (item.itemState & ODS_FOCUS) { InflateRect(&area,-s(5),-s(5)); DrawFocusRect(item.hDC,&area); }
        SelectObject(item.hDC,oldFont);
    }
    void updateCapacity() {
        if (!image_) return;
        if (page_ == Page::Extract) {
            setText(Capacity,L"Контейнер найден. Подлинность данных будет проверена по паролю."); return;
        }
        const auto capacity=image_->capacityBytes();
        std::wostringstream dimensions;
        dimensions << image_->width << L" × " << image_->height;
        std::wstring line=L"Вместимость: " + formatBytes(capacity) + L"  ·  " + dimensions.str();
        const auto secret=text(SecretPath);
        if (!secret.empty()) {
            std::error_code error;
            const auto size=std::filesystem::file_size(std::filesystem::path(secret),error);
            if (!error) {
                const auto nameSize=std::filesystem::path(secret).filename().u8string().size();
                const auto needed=std::uint64_t(82)+nameSize+size;
                line += needed <= capacity ? L"  ·  файл помещается" : L"  ·  файл не помещается";
            }
        }
        setText(Capacity,line);
    }
    void busy(bool value,const std::wstring& description=L"") {
        busy_=value;
        for (const auto window : children_) {
            wchar_t name[32]{}; GetClassNameW(window,name,32);
            if (lstrcmpiW(name,L"BUTTON") == 0 || lstrcmpiW(name,L"EDIT") == 0) EnableWindow(window,!value);
        }
        if (child(Progress)) { ShowWindow(child(Progress),value ? SW_SHOW : SW_HIDE); SendMessageW(child(Progress),PBM_SETMARQUEE,value ? TRUE : FALSE,35); }
        setText(Status,description);
        InvalidateRect(hwnd_,nullptr,FALSE);
    }
    void start(std::unique_ptr<WorkItem> work) {
        work->owner=hwnd_;
        busy(true,work->kind == WorkKind::Inspect ? L"Читаем изображение…" : work->kind == WorkKind::Hide ? L"Шифруем и сохраняем файл…" : work->kind == WorkKind::SaveExtract ? L"Сохраняем восстановленный файл…" : L"Проверяем пароль и восстанавливаем файл…");
        worker_=CreateThread(nullptr,0,workerEntry,work.get(),0,nullptr);
        if (!worker_) { busy(false); throw Error("Не удалось запустить обработку. Попробуйте ещё раз."); }
        work.release();
    }
    std::wstring choose(bool save,bool imageFilter,const std::wstring& initial=L"",bool overwritePrompt=true) {
        std::vector<wchar_t> buffer(32768,L'\0');
        if (!initial.empty() && initial.size() < buffer.size()) std::copy(initial.begin(),initial.end(),buffer.begin());
        const wchar_t* filter=imageFilter ? (save ? L"PNG (*.png)\0*.png\0\0" : L"Изображения PNG/BMP\0*.png;*.bmp\0Все файлы\0*.*\0\0") : L"Все файлы\0*.*\0\0";
        OPENFILENAMEW dialog{}; dialog.lStructSize=sizeof(dialog); dialog.hwndOwner=hwnd_;
        dialog.lpstrFilter=filter; dialog.lpstrFile=buffer.data(); dialog.nMaxFile=static_cast<DWORD>(buffer.size());
        dialog.lpstrTitle=save ? L"Сохранить результат" : L"Выбрать файл";
        dialog.Flags=OFN_EXPLORER | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_ENABLESIZING;
        const auto extension=std::filesystem::path(initial).extension().wstring();
        if (save) {
            if (overwritePrompt) dialog.Flags |= OFN_OVERWRITEPROMPT;
            dialog.lpstrDefExt=imageFilter ? L"png" : extension.empty() ? nullptr : extension.c_str()+1;
        }
        else dialog.Flags |= OFN_FILEMUSTEXIST;
        const bool accepted=save ? GetSaveFileNameW(&dialog) != FALSE : GetOpenFileNameW(&dialog) != FALSE;
        if (!accepted) {
            if (CommDlgExtendedError()) throw Error("Не удалось открыть окно выбора файла.");
            return {};
        }
        return buffer.data();
    }
    void browse(int id) {
        if (id == BrowseImage) {
            const auto path=choose(false,true);
            if (path.empty()) return;
            setText(ImagePath,path);
            if (page_ == Page::Hide && text(OutputPath).empty()) {
                const std::filesystem::path source(path);
                const auto suggested=source.parent_path() / (source.stem().wstring()+L"-stego.png");
                setText(OutputPath,suggested.wstring());
            }
        } else if (id == BrowseSecret) {
            const auto path=choose(false,false);
            if (!path.empty()) { setText(SecretPath,path); updateCapacity(); }
        } else {
            const auto path=choose(true,page_ == Page::Hide,text(OutputPath));
            if (!path.empty()) {
                setText(OutputPath,path); approvedOverwrite_.clear();
                if (std::filesystem::exists(std::filesystem::path(path))) approvedOverwrite_=std::filesystem::path(path);
            }
        }
    }
    void submit() {
        const auto imagePath=text(ImagePath), filePath=text(SecretPath), outputPath=text(OutputPath);
        if (imagePath.empty()) throw Error("Сначала выберите изображение.");
        if (page_ == Page::Hide && filePath.empty()) throw Error("Выберите файл, который нужно спрятать.");
        if (page_ == Page::Hide && outputPath.empty()) throw Error("Укажите имя и место сохранения результата.");
        struct PasswordText { std::wstring value; ~PasswordText() { secureErase(value.data(),value.size()*sizeof(wchar_t)); } } password{text(Password)};
        if (password.value.empty()) throw Error("Введите пароль.");
        if (page_ == Page::Hide && characterCount(password.value) < 8) throw Error("Пароль должен содержать минимум 8 символов.");
        const std::filesystem::path source(imagePath), secret(filePath), out(outputPath);
        if (page_ == Page::Hide && (sameFile(source,out) || sameFile(secret,out)))
            throw Error("Выходной файл должен отличаться от исходных файлов. Выберите другое имя.");
        if (page_ == Page::Hide) {
            auto extension=out.extension().wstring();
            std::transform(extension.begin(),extension.end(),extension.begin(),[](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
            if (extension != L".png") throw Error("Сохраняйте контейнер с расширением .png.");
        }
        bool overwrite=false;
        if (page_ == Page::Hide && std::filesystem::exists(out)) {
            if (out == approvedOverwrite_) overwrite=true;
            else {
                const auto question=L"Файл уже существует:\n" + out.wstring() + L"\n\nЗаменить его после успешной обработки?";
                if (MessageBoxW(hwnd_,question.c_str(),L"Подтверждение сохранения",MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) != IDYES) return;
                overwrite=true;
            }
        }
        auto work=std::make_unique<WorkItem>();
        work->kind=page_ == Page::Hide ? WorkKind::Hide : WorkKind::Extract;
        work->imagePath=source; work->filePath=secret; work->outputPath=out; work->overwrite=overwrite;
        if (image_ && source == cachedPath_) work->image=image_;
        work->password.bytes=passwordBytes(password.value);
        setText(Password,L"");
        start(std::move(work));
    }
    void result(bool success,const std::wstring& body,const std::wstring& path=L"") {
        resultBody_=body; resultPath_=path;
        page(success ? Page::Success : Page::Failure);
    }
    void complete(WorkResult& value) {
        if (worker_) { WaitForSingleObject(worker_,INFINITE); CloseHandle(worker_); worker_=nullptr; }
        busy(false);
        if (!value.success) { result(false,value.message.empty() ? L"Не удалось обработать файл. Возможно, недостаточно оперативной памяти." : value.message); return; }
        if (value.kind == WorkKind::Inspect) {
            image_=std::move(value.image); cachedPath_=value.imagePath; updateCapacity(); return;
        }
        if (value.kind == WorkKind::Extract) {
            if (!value.recovered) throw Error("Missing recovered file");
            const auto suggested=value.imagePath.parent_path() / std::filesystem::u8path(value.recovered->name);
            const auto selected=choose(true,false,suggested.wstring(),false);
            if (selected.empty()) {
                setText(Status,L"Сохранение отменено. Чтобы повторить, введите пароль и нажмите «Извлечь файл».");
                SetFocus(child(Password));
                return;
            }
            const std::filesystem::path out(selected);
            if (sameFile(value.imagePath,out))
                throw Error("Выходной файл должен отличаться от изображения-контейнера. Выберите другое имя.");
            const bool overwrite=std::filesystem::exists(out);
            if (overwrite) {
                const auto question=L"Файл уже существует:\n" + out.wstring() + L"\n\nЗаменить его восстановленным файлом?";
                if (MessageBoxW(hwnd_,question.c_str(),L"Подтверждение сохранения",MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) != IDYES) {
                    setText(Status,L"Замена отменена. Чтобы повторить, введите пароль и нажмите «Извлечь файл».");
                    return;
                }
            }
            auto work=std::make_unique<WorkItem>();
            work->kind=WorkKind::SaveExtract;
            work->imagePath=value.imagePath;
            work->outputPath=out;
            work->overwrite=overwrite;
            work->recovered=std::move(value.recovered);
            start(std::move(work));
            return;
        }
        std::wstring body;
        if (value.kind == WorkKind::Hide) {
            body=L"Файл зашифрован и сохранён внутри PNG.\nРазмер исходного файла: " + formatBytes(value.fileSize) + L".";
            if (std::isfinite(value.psnr)) { std::wostringstream number; number << std::fixed << std::setprecision(2) << value.psnr; body += L"  PSNR: " + number.str() + L" dB."; }
        } else body=L"Пароль и целостность данных проверены.\nФайл восстановлен: " + formatBytes(value.fileSize) + L".";
        image_.reset(); cachedPath_.clear();
        result(true,body,value.outputPath.wstring());
    }
    void command(int id,int notification) {
        if (busy_ || building_) return;
        if (id == HomeHide) page(Page::Hide);
        else if (id == HomeExtract) page(Page::Extract);
        else if (id == Back || id == ResultHome) page(Page::Home);
        else if (id == Exit) SendMessageW(hwnd_,WM_CLOSE,0,0);
        else if (id == BrowseImage || id == BrowseSecret || id == BrowseOutput) browse(id);
        else if (id == Action) submit();
        else if (id == ImagePath && notification == EN_CHANGE) {
            image_.reset(); cachedPath_.clear();
            const auto selected=text(ImagePath);
            if (!selected.empty()) {
                auto work=std::make_unique<WorkItem>(); work->kind=WorkKind::Inspect;
                work->extractInspection=page_ == Page::Extract;
                work->imagePath=std::filesystem::path(selected);
                start(std::move(work));
            }
        }
        else if (id == ShowPassword) {
            const bool show=SendMessageW(child(ShowPassword),BM_GETCHECK,0,0) == BST_CHECKED;
            SendMessageW(child(Password),EM_SETPASSWORDCHAR,show ? 0 : 0x25cf,0); InvalidateRect(child(Password),nullptr,TRUE);
        } else if (id == SecretPath && notification == EN_CHANGE) updateCapacity();
        else if (id == OutputPath && notification == EN_CHANGE) approvedOverwrite_.clear();
    }
    LRESULT message(UINT kind,WPARAM wParam,LPARAM lParam) {
        switch (kind) {
        case WM_CREATE: page(Page::Home); return 0;
        case WM_SIZE: layout(); InvalidateRect(hwnd_,nullptr,FALSE); return 0;
        case WM_GETMINMAXINFO: {
            auto* limits=reinterpret_cast<MINMAXINFO*>(lParam);
            limits->ptMinTrackSize.x=s(800); limits->ptMinTrackSize.y=s(690); return 0;
        }
        case WM_ERASEBKGND: return 1;
        case WM_PAINT: paint(); return 0;
        case WM_PRINTCLIENT: paint(reinterpret_cast<HDC>(wParam)); return 0;
        case WM_DRAWITEM: if (wParam) { drawButton(*reinterpret_cast<DRAWITEMSTRUCT*>(lParam)); return TRUE; } break;
        case WM_CTLCOLORSTATIC:
        case WM_CTLCOLOREDIT: {
            const auto dc=reinterpret_cast<HDC>(wParam); const int id=GetDlgCtrlID(reinterpret_cast<HWND>(lParam));
            SetBkMode(dc,TRANSPARENT);
            SetTextColor(dc,id == ResultTitle ? (page_ == Page::Failure ? ErrorRed : Accent) :
                              id == Capacity || id == 2005 || id == Status ? Muted : Ink);
            SetBkColor(dc,Panel);
            return reinterpret_cast<LRESULT>(panelBrush_);
        }
        case WM_COMMAND: command(LOWORD(wParam),HIWORD(wParam)); return 0;
        case WorkDone: {
            std::unique_ptr<WorkResult> value(reinterpret_cast<WorkResult*>(lParam));
            if (value) complete(*value);
            else {
                if (worker_) { WaitForSingleObject(worker_,INFINITE); CloseHandle(worker_); worker_=nullptr; }
                busy(false); result(false,L"Недостаточно памяти для обработки файла.");
            }
            return 0;
        }
        case WM_CLOSE:
            if (busy_) { MessageBoxW(hwnd_,L"Дождитесь завершения обработки. Это окно можно будет закрыть после операции.",L"Обработка файла",MB_OK | MB_ICONINFORMATION); return 0; }
            setText(Password,L""); DestroyWindow(hwnd_); return 0;
        case WM_DESTROY: PostQuitMessage(0); return 0;
        }
        return DefWindowProcW(hwnd_,kind,wParam,lParam);
    }
    static LRESULT CALLBACK windowProcedure(HWND window,UINT kind,WPARAM wParam,LPARAM lParam) {
        auto* self=reinterpret_cast<Application*>(GetWindowLongPtrW(window,GWLP_USERDATA));
        if (kind == WM_NCCREATE) {
            self=static_cast<Application*>(reinterpret_cast<CREATESTRUCTW*>(lParam)->lpCreateParams);
            self->hwnd_=window; SetWindowLongPtrW(window,GWLP_USERDATA,reinterpret_cast<LONG_PTR>(self));
        }
        if (!self) return DefWindowProcW(window,kind,wParam,lParam);
        try { return self->message(kind,wParam,lParam); }
        catch (const std::exception& error) {

            if (kind == WM_CREATE) return -1;
            if (self->busy_) self->busy(false);
            try { self->result(false,explainError(error)); }
            catch (...) { MessageBoxW(window,L"Не удалось обновить интерфейс.",L"DataStego",MB_OK | MB_ICONERROR); }
            return 0;
        }
    }
};
}

int GUIController::run(int showCommand) const { return Application{}.run(showCommand); }
}
