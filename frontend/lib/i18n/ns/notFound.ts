import { defineMessages } from "../core";

/** The 404 page (app/not-found.tsx). */
export const notFound = defineMessages({
  en: {
    code: "Error 404",
    title: "Page not found",
    text: "The page you're looking for doesn't exist or has been moved. Check the address, or head back to the home page.",
    home: "Go to the home page",
  },
  ru: {
    code: "Ошибка 404",
    title: "Страница не найдена",
    text: "Такой страницы нет, или она была перемещена. Проверьте адрес или вернитесь на главную.",
    home: "На главную",
  },
  uz: {
    code: "Xatolik 404",
    title: "Sahifa topilmadi",
    text: "Siz qidirayotgan sahifa mavjud emas yoki boshqa joyga ko'chirilgan. Manzilni tekshiring yoki bosh sahifaga qayting.",
    home: "Bosh sahifaga qaytish",
  },
});
