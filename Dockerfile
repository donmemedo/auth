FROM python:3.10
ENV TZ=Asia/Tehran
COPY . /app
WORKDIR /app
RUN pip install  -U pip
RUN RUN pip install  -r requirements.txt
RUN ls
ENV PYTHONPATH="$PYTHONPATH:/app"
WORKDIR /app/src
EXPOSE 8000
EXPOSE 6060	
EXPOSE 4040
CMD python main.py
#CMD uvicorn main:app --host 0.0.0.0 --port 8000