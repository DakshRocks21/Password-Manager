from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.popup import Popup
from kivy.uix.screenmanager import Screen
from password_manager import PasswordManager  # Import the PasswordManager class

class LoginScreen(Screen):
    def __init__(self, **kwargs):
        super(LoginScreen, self).__init__(**kwargs)
        self.password_manager = PasswordManager()  # Initialize the PasswordManager instance

        layout = BoxLayout(orientation='vertical', padding=10, spacing=10)
        layout.add_widget(Label(text="Master Password:"))
        
        self.master_password_input = TextInput(password=True)
        layout.add_widget(self.master_password_input)
        
        layout.add_widget(Button(text="Login", on_press=self.login))
        
        self.add_widget(layout)

    def login(self, instance):
        master_password = self.master_password_input.text
        if self.password_manager.check_master_password(master_password):
            self.manager.current = 'main'  # Switch to the main screen
        else:
            popup = Popup(title='Login Failed',
                          content=Label(text='Incorrect master password!'),
                          size_hint=(None, None), size=(400, 200))
            popup.open()

    def set_password_manager(self, password_manager):
        """Set the password manager instance from outside if needed."""
        self.password_manager = password_manager
