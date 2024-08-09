from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.popup import Popup
from kivy.uix.screenmanager import Screen

class MainScreen(Screen):
    def __init__(self, **kwargs):
        super(MainScreen, self).__init__(**kwargs)
        self.password_manager = None  # This will be set using set_password_manager method

        # Main layout
        layout = BoxLayout(orientation='vertical', padding=10, spacing=10)

        # Add service and password input fields
        self.service_input = TextInput(hint_text='Service Name')
        self.password_input = TextInput(hint_text='Password', password=True)

        layout.add_widget(Label(text="Service:"))
        layout.add_widget(self.service_input)
        layout.add_widget(Label(text="Password:"))
        layout.add_widget(self.password_input)

        # Buttons for adding and retrieving passwords
        layout.add_widget(Button(text="Add Password", on_press=self.add_password))
        layout.add_widget(Button(text="Retrieve Password", on_press=self.retrieve_password))
        layout.add_widget(Button(text="Show All Services", on_press=self.show_all_services))

        # Logout button
        layout.add_widget(Button(text="Logout", on_press=self.logout))

        self.add_widget(layout)

    def set_password_manager(self, password_manager):
        """Set the password manager instance."""
        self.password_manager = password_manager

    def add_password(self, instance):
        service = self.service_input.text.strip()
        password = self.password_input.text.strip()
        if service and password:
            self.password_manager.add_password(service, password)
            popup = Popup(title='Success',
                          content=Label(text=f'Password for {service} added successfully.'),
                          size_hint=(None, None), size=(400, 200))
            popup.open()
            self.service_input.text = ''
            self.password_input.text = ''
        else:
            popup = Popup(title='Error',
                          content=Label(text='Service name and password cannot be empty.'),
                          size_hint=(None, None), size=(400, 200))
            popup.open()

    def retrieve_password(self, instance):
        service = self.service_input.text.strip()
        if service:
            password = self.password_manager.get_password(service)
            if password:
                popup = Popup(title='Password Retrieved',
                              content=Label(text=f'Password for {service}: {password}'),
                              size_hint=(None, None), size=(400, 200))
                popup.open()
            else:
                popup = Popup(title='Error',
                              content=Label(text=f'No password found for {service}.'),
                              size_hint=(None, None), size=(400, 200))
                popup.open()
        else:
            popup = Popup(title='Error',
                          content=Label(text='Please enter a service name to retrieve the password.'),
                          size_hint=(None, None), size=(400, 200))
            popup.open()

    def show_all_services(self, instance):
        services = self.password_manager.get_all_services()
        if services:
            services_text = '\n'.join(services)
            popup = Popup(title='Stored Services',
                          content=Label(text=f'Services:\n{services_text}'),
                          size_hint=(None, None), size=(400, 400))
            popup.open()
        else:
            popup = Popup(title='No Services',
                          content=Label(text='No services found in the password manager.'),
                          size_hint=(None, None), size=(400, 200))
            popup.open()

    def logout(self, instance):
        self.manager.current = 'login'
