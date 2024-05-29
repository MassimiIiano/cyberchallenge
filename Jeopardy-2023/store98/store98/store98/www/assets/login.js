async function login(username, password) {
	document.querySelector('#loginError').style.display = 'none';
	try {
		const res = await fetch('/api/v1/session', {
			credentials: 'same-origin',
			method: 'POST',
			headers: {
				'Content-Type': 'application/json'
			},
			body: JSON.stringify({
				username: username,
				password: password
			})
		});
		if (!res.ok) {
			document.querySelector('#loginError').innerText = 'Wrong username or password.';
			document.querySelector('#loginError').style.display = 'block';
			return;
		}
		const data = await res.json();

		document.querySelector('#loginTitle').innerText = 'Welcome';

		const welcomeMessage = document.createElement('div');
		welcomeMessage.innerText = `Welcome back ${username}!`;

		document.querySelector('#loginForm').parentElement.appendChild(welcomeMessage);
		document.querySelector('#loginForm').parentElement.removeChild(document.querySelector('#loginForm'));

		if (data.flag) {
			renderFlag(data.flag);
			Clippy.stop();
			Clippy.play('Congratulate');
		}
	} catch {
		document.querySelector('#loginError').innerText = "There was an error. Please don't ask for more details.";
		document.querySelector('#loginError').style.display = 'block';
	}
}

async function register(username, password) {
	document.querySelector('#loginError').style.display = 'none';
	try {
		const res = await fetch('/api/v1/users', {
			credentials: 'same-origin',
			method: 'POST',
			headers: {
				'Content-Type': 'application/json'
			},
			body: JSON.stringify({
				username: username,
				password: password
			})
		});
		if (!res.ok) {
			document.querySelector('#loginError').innerText = 'Username already taken';
			document.querySelector('#loginError').style.display = 'block';
			return;
		}
		await login(username, password);
	} catch {
		document.querySelector('#loginError').innerText = "There was an error. Please don't ask for more details.";
		document.querySelector('#loginError').style.display = 'block';
	}
}

function handleFormSubmit(event) {
	event.preventDefault();

	const username = document.querySelector('#username').value.trim();
	const password = document.querySelector('#password').value.trim();

	if (username.length === 0 || password.length === 0) {
		return;
	}

	const selection = document.querySelector('#login').checked;

	// Sometimes writing cursed code is fun
	(selection ? login : register)(username, password);
}

document.querySelector('#loginForm').onsubmit = handleFormSubmit;
