from kivy.app import App
from kivy.uix.screenmanager import ScreenManager, FadeTransition
from login import LoginScreen
from main_screen import MainScreen
from password_manager import PasswordManager

class PasswordManagerApp(App):
    def build(self):
        self.password_manager = PasswordManager()

        sm = ScreenManager(transition=FadeTransition())

        # Create LoginScreen and set the password manager
        login_screen = LoginScreen(name='login')
        login_screen.set_password_manager(self.password_manager)

        # Create MainScreen and pass the password manager using set_password_manager method
        main_screen = MainScreen(name='main')
        main_screen.set_password_manager(self.password_manager)

        # Add screens to the ScreenManager
        sm.add_widget(login_screen)
        sm.add_widget(main_screen)

        return sm

if __name__ == '__main__':
    PasswordManagerApp().run()
