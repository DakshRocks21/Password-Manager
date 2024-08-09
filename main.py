from kivy.app import App
from kivy.uix.screenmanager import ScreenManager, FadeTransition, Screen
from login import LoginScreen
from password_manager import PasswordManager
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.popup import Popup
from kivy.uix.slider import Slider
from kivy.uix.recycleview import RecycleView
import random
import string

class MainScreen(Screen):
    def __init__(self, **kwargs):
        super(MainScreen, self).__init__(**kwargs)
        self.password_manager = None  # Initialize as None

        layout = GridLayout(cols=2, padding=10, spacing=10)

        self.service_label = Label(text="Service:")
        layout.add_widget(self.service_label)

        self.service_input = TextInput()
        layout.add_widget(self.service_input)

        self.password_label = Label(text="Password:")
        layout.add_widget(self.password_label)

        self.password_input = TextInput(password=True)
        layout.add_widget(self.password_input)

        self.password_strength_label = Label(text="Strength:")
        layout.add_widget(self.password_strength_label)

        self.password_strength_slider = Slider(min=0, max=10, value=0)
        layout.add_widget(self.password_strength_slider)

        self.add_password_button = Button(text="Add Password", on_press=self.add_password)
        layout.add_widget(self.add_password_button)

        self.get_password_button = Button(text="Get Password", on_press=self.get_password)
        layout.add_widget(self.get_password_button)

        self.delete_password_button = Button(text="Delete Password", on_press=self.delete_password)
        layout.add_widget(self.delete_password_button)

        self.password_generator_button = Button(text="Generate Password", on_press=self.generate_password)
        layout.add_widget(self.password_generator_button)

        self.service_list = RecycleView()  # Implement the service list as needed
        layout.add_widget(self.service_list)

        self.add_widget(layout)

    def set_password_manager(self, password_manager):
        """Set the password manager after initialization."""
        self.password_manager = password_manager
        self.update_service_list()

    def add_password(self, instance):
        service = self.service_input.text
        password = self.password_input.text
        if service and password:
            self.password_manager.add_password(service, password)
            self.update_service_list()
            popup = Popup(title='Success',
                          content=Label(text=f'Password for {service} added successfully!'),
                          size_hint=(None, None), size=(400, 200))
            popup.open()

    def get_password(self, instance):
        service = self.service_input.text
        if service:
            password = self.password_manager.get_password(service)
            if password:
                popup = Popup(title='Password Found',
                              content=Label(text=f'The password for {service} is {password}'),
                              size_hint=(None, None), size=(400, 200))
                popup.open()
            else:
                popup = Popup(title='Not Found',
                              content=Label(text=f'No password found for {service}.'),
                              size_hint=(None, None), size=(400, 200))
                popup.open()

    def delete_password(self, instance):
        service = self.service_input.text
        if service:
            self.password_manager.delete_password(service)
            self.update_service_list()
            popup = Popup(title='Success',
                          content=Label(text=f'Password for {service} deleted successfully!'),
                          size_hint=(None, None), size=(400, 200))
            popup.open()

    def generate_password(self, instance):
        length = random.randint(8, 16)
        password = ''.join(random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(length))
        self.password_input.text = password
        self.update_password_strength(None)

    def update_password_strength(self, instance):
        password = self.password_input.text
        strength = self.check_password_strength(password)
        self.password_strength_slider.value = strength

    def check_password_strength(self, password):
        if len(password) < 6:
            return 2
        elif len(password) < 10:
            return 5
        elif len(password) >= 10 and any(c.isdigit() for c in password) and any(c.islower() for c in password) and any(c.isupper() for c in password) and any(c in string.punctuation for c in password):
            return 10
        return 7

    def update_service_list(self):
        services = self.password_manager.get_all_services()
        # Update the RecycleView with services data

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
